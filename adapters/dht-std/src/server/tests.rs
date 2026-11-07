//! Host composition using real private UDP endpoints and the real pure router.
//! The local PILS identity and peer protocol inputs are explicit model inputs;
//! no PILS/CORE service, normal daemon or C interoperability is asserted.
use super::*;
use gnunet_client_host::EndpointSource;
use gnunet_service_runtime::clock::SystemClock;
use gnunet_wire::official::dht::{GetMessage, Path, ResultMessage, RouteOptions};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct FixedEntropy;
impl Entropy for FixedEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Fault> {
        bytes.fill(1);
        Ok(())
    }
}
async fn next<'id>(server: &mut Server<'id>) -> TestResult<crate::ip::Event<'id>> {
    loop {
        let ip = server.ip.as_mut().ok_or(Fault::NotReady)?;
        let event = timeout(Duration::from_secs(2), poll_fn(|cx| ip.poll(cx))).await??;
        if matches!(event, crate::ip::Event::AddressesChanged { .. }) {
            server.ip_event(event)?;
        } else {
            return Ok(event);
        }
    }
}
fn response(key: &[u8; 64], expiration: u64, payload: &[u8]) -> TestResult<Vec<u8>> {
    let result = ResultMessage {
        block_type: 65000,
        reserved: 0,
        options: RouteOptions::NONE,
        expiration: AbsoluteTime::from_micros(expiration),
        key,
        truncated_peer: None,
        put_path: Path::empty(),
        get_path: Path::empty(),
        sender_signature: None,
        payload,
    };
    let mut bytes = vec![0; result.encoded_len()?];
    result.encode(&mut bytes)?;
    Ok(bytes)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The finite component case asserts actual endpoint generations, router effects and datagram retirement"
)]
fn shared_peer_retains_reverse_route_until_last_endpoint_and_never_retargets_original_work()
-> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        timeout(Duration::from_secs(8), async {
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            // These selectors are never polled. No native PILS/CORE identity
            // or source fact is synthesized from their unused path.
            let source = || EndpointSource::unix_with_clock(std::env::temp_dir().join("gnunet-dht-unused-model-source"), clock.clone());
            let ports = Ports { core: source(), pils: source(), nse: source(), peerstore: source(), transport: source(),
                clock, options: Default::default(), unix: Default::default() };
            let limits = Limits { underlays: Underlays { gnunet: false, ip: Some(crate::ip::Config {
                bind: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), port: 0, targets: 3, sends: 1,
                ..crate::ip::Config::default() }) }, try_connect: false, ..Limits::default() };
            let blocks = Blocks { plugins: Vec::new(), group_profile: limits.network.group_profile,
                hello_profile: limits.pils_profile.hello() };
            let mut instances = Instances::default();
            let mut server = Server::new(&mut instances, ports, limits, blocks)?;
            let model_local = [1; 32];
            server.routing_identity = Some(model_local);
            server.ip.as_mut().ok_or(Fault::NotReady)?.set_identity(model_local)?;
            server.owner = Some(NetworkOwner::new(server.local.take().ok_or(Fault::NotReady)?, model_local,
                limits.network, network::Policy { estimate: gnunet_dht::routing::Estimate::new(1.0)? })?);
            let first = UdpSocket::bind("127.0.0.1:0").await?;
            let second = UdpSocket::bind("127.0.0.1:0").await?;
            let supplier = UdpSocket::bind("127.0.0.1:0").await?;
            let mut native = Vec::new();
            for (identity, endpoint) in [([2; 32], first.local_addr()?), ([2; 32], second.local_addr()?), ([3; 32], supplier.local_addr()?)] {
                let peer = server.ip.as_mut().ok_or(Fault::NotReady)?.try_connect(identity, format!("ip+udp://{endpoint}").as_bytes())?;
                let event = next(&mut server).await?;
                assert!(matches!(event, crate::ip::Event::Connected(actual) if actual == peer));
                server.ip_event(event)?;
                native.push(peer);
            }
            let token = server.peers[0].token;
            assert_eq!(server.peers[1].token, token);
            assert_ne!(server.peers[2].token, token);
            let anchor = server.anchor()?;
            let key = [9; 64];
            // A complete incoming GET creates an actual reverse route. Marking
            // every peer visited keeps this case independent of fanout draws.
            let get = GetMessage { block_type: 65000, options: RouteOptions::NONE, hop_count: 0,
                desired_replication_level: 1, peer_bloom: &[255; 128], key: &key,
                result_filter: &[], extended_query: &[] };
            let mut request = vec![0; get.encoded_len()?]; get.encode(&mut request)?;
            server.ingest_native(NativePeer::Ip(native[0]), &request, anchor, &mut FixedEntropy)?;
            assert_eq!(server.owner.as_ref().ok_or(Fault::NotReady)?.snapshot().routes, 1);
            let first_reply = response(&key, anchor.now + 5_000_000, b"original blocked reply")?;
            server.ingest_native(NativePeer::Ip(native[2]), &first_reply, anchor, &mut FixedEntropy)?;
            let (original, original_frame) = server.owner.as_ref().ok_or(Fault::NotReady)?.work().find_map(|work| match work {
                Work::Send { job, peer, kind: JobKind::Result, frame, .. } if peer == token => Some((job, frame.as_ptr())), _ => None,
            }).ok_or(Fault::NotReady)?;
            // Fill the real one-datagram native queue before the router chooses
            // its endpoint. No socket write occurs until the owner is polled.
            let bound = Bound::new(server.clock.as_ref(), Duration::from_secs(2))?;
            assert!(server.send_frame(NativePeer::Ip(native[0]), None, &request, bound)?);
            assert!(!server.work()?);
            assert!(server.owner.as_ref().ok_or(Fault::NotReady)?.work().any(|work| matches!(work,
                Work::Send { job, frame, .. } if job == original && frame.as_ptr() == original_frame)));
            assert_eq!(server.sends.len(), 1);
            assert!(server.sends[0].job.is_none());
            assert_eq!(server.jobs.iter().find(|job| job.job == original).ok_or(Fault::NotReady)?.target,
                Some(NativePeer::Ip(native[0])));
            let row = &server.jobs[native_job_index(&server.jobs, original)?];
            let captured = (row.bound.until, row.bound.hard, row.target, row.cancelled);
            let later = server.anchor()?;
            server.sync_jobs(later)?;
            let row = &server.jobs[native_job_index(&server.jobs, original)?];
            assert_eq!((row.bound.until, row.bound.hard, row.target, row.cancelled), captured);
            assert!(matches!(server.ip.as_mut().ok_or(Fault::NotReady)?.try_connect([4; 32], b"ip+udp://127.0.0.1:1"),
                Err(crate::ip::Error::Protocol(Fault::WouldBlock))));
            let event = next(&mut server).await?;
            assert!(matches!(event, crate::ip::Event::Finished { peer, outcome: crate::ip::Outcome::Disconnected(crate::ip::DisconnectReason::Evicted), written: 0, .. } if peer == native[0]));
            server.ip_event(event)?;
            let event = next(&mut server).await?;
            assert!(matches!(event, crate::ip::Event::Disconnected { peer, .. } if peer == native[0]));
            server.ip_event(event)?;
            assert!(server.owner.as_ref().ok_or(Fault::NotReady)?.jobs().all(|job| job.job != original));
            assert!(!server.work()?);
            assert_eq!(server.owner.as_ref().ok_or(Fault::NotReady)?.snapshot().routes, 1);
            // A different real router result still follows that retained route
            // through the surviving endpoint. It is a new job, never old work.
            let next_reply = response(&key, anchor.now + 5_000_000, b"new independently routed reply")?;
            server.ingest_native(NativePeer::Ip(native[2]), &next_reply, anchor, &mut FixedEntropy)?;
            let next_job = server.owner.as_ref().ok_or(Fault::NotReady)?.work().find_map(|work| match work {
                Work::Send { job, peer, .. } if peer == token => Some(job), _ => None,
            }).ok_or(Fault::NotReady)?;
            let original_bound = server.jobs.iter().find(|job| job.job == next_job).ok_or(Fault::NotReady)?;
            let (until, hard) = (original_bound.bound.until, original_bound.bound.hard);
            let admitted = server.report.ip_admitted;
            assert!(server.work()?);
            // Pure ownership transfers only after the real native FIFO has
            // accepted the same job, target and fixed original deadline.
            assert!(server.owner.as_ref().ok_or(Fault::NotReady)?.jobs().all(|job| job.job != next_job));
            assert_eq!(server.sends.len(), 1);
            assert_eq!(server.sends[0].job, Some(next_job));
            assert_eq!(server.sends[0].peer, NativePeer::Ip(native[1]));
            assert_eq!(server.sends[0].bound.until, until);
            assert_eq!(server.sends[0].bound.hard, hard);
            assert_eq!(server.report.ip_admitted, admitted + 1);
            assert!(!server.work()?);
            assert_eq!(server.sends.len(), 1);
            assert_eq!(server.report.ip_admitted, admitted + 1);
            let event = next(&mut server).await?;
            assert!(matches!(event, crate::ip::Event::Finished { peer, outcome: crate::ip::Outcome::Written, .. } if peer == native[1]));
            server.ip_event(event)?;
            let mut bytes = [0; 1024];
            let (length, _) = timeout(Duration::from_secs(2), second.recv_from(&mut bytes)).await??;
            assert_eq!(&bytes[..32], &model_local);
            assert_eq!(ResultMessage::decode(&bytes[32..length])?.payload, b"new independently routed reply");
            assert!(matches!(first.try_recv_from(&mut bytes), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
            assert!(matches!(second.try_recv_from(&mut bytes), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
            assert!(matches!(server.ip.as_mut().ok_or(Fault::NotReady)?.try_connect([4; 32], format!("ip+udp://{}", second.local_addr()?).as_bytes()),
                Err(crate::ip::Error::Protocol(Fault::WouldBlock))));
            let event = next(&mut server).await?;
            assert!(matches!(event, crate::ip::Event::Disconnected { peer, .. } if peer == native[1]));
            server.ip_event(event)?;
            assert_eq!(server.owner.as_ref().ok_or(Fault::NotReady)?.snapshot().routes, 0);
            assert!(server.peers.iter().all(|peer| peer.token != token));
            let final_reply = response(&key, anchor.now + 5_000_000, b"no route after final retirement")?;
            server.ingest_native(NativePeer::Ip(native[2]), &final_reply, anchor, &mut FixedEntropy)?;
            assert!(!server.work()?);
            server.begin_close();
            loop {
                if matches!(poll_fn(|cx| server.poll_close(cx, &mut |_| {})).await?, Progress::Closed) { break; }
            }
            assert!(server.into_report().quiescent);
            Ok::<_, Box<dyn std::error::Error>>(())
        }).await??;
        Ok(())
    })
}

fn model_server<'id>(
    instances: &'id mut Instances,
    core: Option<EndpointSource>,
) -> TestResult<Server<'id>> {
    let clock: Arc<dyn RuntimeClock> = core.as_ref().map_or_else(
        || Arc::new(SystemClock) as Arc<dyn RuntimeClock>,
        EndpointSource::clock,
    );
    let unused = || {
        EndpointSource::unix_with_clock(
            std::env::temp_dir().join("gn-dht-unused-model-source"),
            clock.clone(),
        )
    };
    let gnunet = core.is_some();
    let ports = Ports {
        core: core.unwrap_or_else(unused),
        pils: unused(),
        nse: unused(),
        peerstore: unused(),
        transport: unused(),
        clock,
        options: Default::default(),
        unix: Default::default(),
    };
    let limits = Limits {
        underlays: Underlays {
            gnunet,
            ip: Some(crate::ip::Config {
                bind: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port: 0,
                targets: 4,
                sends: 1,
                ..crate::ip::Config::default()
            }),
        },
        try_connect: false,
        ..Limits::default()
    };
    let blocks = Blocks {
        plugins: Vec::new(),
        group_profile: limits.network.group_profile,
        hello_profile: limits.pils_profile.hello(),
    };
    let mut server = Server::new(instances, ports, limits, blocks)?;
    let anchor = server.anchor()?;
    // Explicit public identity model input. No native PILS peer or SIGN receipt
    // is fabricated by this fixture; actual UDP IO below remains independently observed.
    server.observe_identity([1; 32], anchor)?;
    server.owner = Some(NetworkOwner::new(
        server.local.take().ok_or(Fault::NotReady)?,
        [1; 32],
        limits.network,
        network::Policy {
            estimate: gnunet_dht::routing::Estimate::new(1.0)?,
        },
    )?);
    Ok(server)
}
async fn attach_ip<'id>(
    server: &mut Server<'id>,
    identity: [u8; 32],
    socket: &UdpSocket,
) -> TestResult<crate::ip::Peer<'id>> {
    let peer = server.ip.as_mut().ok_or(Fault::NotReady)?.try_connect(
        identity,
        format!("ip+udp://{}", socket.local_addr()?).as_bytes(),
    )?;
    let event = next(server).await?;
    if !matches!(event, crate::ip::Event::Connected(actual) if actual == peer) {
        return Err(Fault::Conflict.into());
    }
    server.ip_event(event)?;
    Ok(peer)
}
async fn close_model(server: &mut Server<'_>) -> TestResult {
    server.begin_close();
    loop {
        if matches!(
            poll_fn(|cx| server.poll_close(cx, &mut |_| {})).await?,
            Progress::Closed
        ) {
            return Ok(());
        }
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The finite native UDP case checks actual original send retirement and a retained PUT's unchanged deadline"
)]
fn identity_change_retires_actual_old_udp_debt_without_replaying_or_renewing_put() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        timeout(Duration::from_secs(8), async {
            let mut instances = Instances::default();
            let mut server = model_server(&mut instances, None)?;
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let old = attach_ip(&mut server, [2; 32], &socket).await?;
            let anchor = server.anchor()?;
            let key = [7; 64];
            let request = GetMessage { block_type: 65000, options: RouteOptions::NONE,
                hop_count: 0, desired_replication_level: 1, peer_bloom: &[255; 128], key: &key,
                result_filter: &[], extended_query: &[] };
            let mut frame = vec![0; request.encoded_len()?]; request.encode(&mut frame)?;
            let bound = Bound::new(server.clock.as_ref(), Duration::from_secs(3))?;
            assert!(server.send_frame(NativePeer::Ip(old), None, &frame, bound)?);
            // An accepted local PUT waits behind that real, unpolled one-frame
            // FIFO. Its original intent is not a native submission or storage ACK.
            let put = ipc::Put { block_type: 65000, options: 0, replication: 1,
                expiration: AbsoluteTime::from_micros(anchor.now + 10_000_000), key: &key,
                payload: b"original unsubmitted body" };
            let mut input = vec![0; put.encoded_len()?]; put.encode(&mut input)?;
            let mut blocks = BuiltinBlocks { context: BlockContext::new(&server.blocks.plugins, server.blocks.group_profile),
                work: BlockWork { hello: &mut server.hello_scratch, hello_limits: server.limits.hello,
                    hello_profile: server.blocks.hello_profile, pow: &mut server.pow } };
            let owner = server.owner.as_mut().ok_or(Fault::NotReady)?;
            let client = owner.connect_client()?;
            owner.ingest_client(client, &input, anchor.now, &mut blocks, &mut FixedEntropy)?;
            server.sync_jobs(anchor)?;
            let original = server.puts.first().ok_or(Fault::NotReady)?;
            let captured = (original.put, original.bound.until, original.bound.hard);
            assert!(!server.work()?);
            // The old remote identity becomes self. Both its logical mapping
            // and the old local prefix retire, without replacing the client owner.
            let later = server.anchor()?;
            server.observe_identity([2; 32], later)?;
            assert!(server.peers.is_empty());
            assert_eq!(server.owner.as_ref().ok_or(Fault::NotReady)?.local_snapshot().clients, 1);
            assert_eq!(server.sends.len(), 1);
            assert_eq!(server.sends[0].peer, NativePeer::Ip(old));
            let original = server.puts.first().ok_or(Fault::NotReady)?;
            assert_eq!((original.put, original.bound.until, original.bound.hard), captured);
            let event = next(&mut server).await?;
            assert!(matches!(event, crate::ip::Event::Finished { peer,
                outcome: crate::ip::Outcome::Disconnected(crate::ip::DisconnectReason::IdentityChanged),
                written: 0, .. } if peer == old));
            server.ip_event(event)?;
            let event = next(&mut server).await?;
            assert!(matches!(event, crate::ip::Event::Disconnected { peer, .. } if peer == old));
            server.ip_event(event)?;
            assert!(server.sends.is_empty());
            let mut received = [0; 2048];
            assert!(matches!(socket.try_recv_from(&mut received), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
            let replacement = attach_ip(&mut server, [3; 32], &socket).await?;
            let now = server.anchor()?;
            let mut blocks = BuiltinBlocks { context: BlockContext::new(&server.blocks.plugins, server.blocks.group_profile),
                work: BlockWork { hello: &mut server.hello_scratch, hello_limits: server.limits.hello,
                    hello_profile: server.blocks.hello_profile, pow: &mut server.pow } };
            server.owner.as_mut().ok_or(Fault::NotReady)?.tick(now.now, &mut blocks, &mut FixedEntropy)?;
            server.sync_jobs(now)?;
            assert!(server.work()?);
            assert_eq!(server.sends.len(), 1);
            assert_eq!(server.sends[0].peer, NativePeer::Ip(replacement));
            assert_eq!(server.sends[0].bound.until, captured.1);
            assert!(server.sends[0].bound.hard <= captured.2);
            assert_eq!(server.owner.as_ref().ok_or(Fault::NotReady)?.put_stats().submitted, 1);
            assert!(!server.work()?);
            let event = next(&mut server).await?;
            assert!(matches!(event, crate::ip::Event::Finished { peer, outcome: crate::ip::Outcome::Written, .. } if peer == replacement));
            server.ip_event(event)?;
            let (length, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut received)).await??;
            assert_eq!(&received[..32], &[2; 32]);
            let actual = gnunet_wire::official::dht::PutMessage::decode(&received[32..length])?;
            assert_eq!(actual.payload, put.payload);
            assert_eq!(actual.expiration, put.expiration);
            assert!(matches!(socket.try_recv_from(&mut received), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
            close_model(&mut server).await?;
            assert!(server.into_report().quiescent);
            Ok::<_, Box<dyn std::error::Error>>(())
        }).await??;
        Ok(())
    })
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gn-dht-identity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
struct Actor(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for Actor {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn core_step(server: &mut Server<'_>) -> TestResult<Event> {
    loop {
        let source = server.core.as_mut().ok_or(Fault::NotReady)?;
        let progress = timeout(
            Duration::from_secs(2),
            poll_fn(|cx| source.client.poll(cx, None)),
        )
        .await??;
        let input = matches!(&progress, core::Progress::Inbound { .. });
        let anchor = server.anchor()?;
        let event = server.core_event(progress, Some(anchor), &mut FixedEntropy)?;
        if input || matches!(&event, Event::Error { .. }) {
            return Ok(event);
        }
    }
}
fn sign_not_ready(result: Result<bool, Error>) -> bool {
    matches!(result, Err(Error(cause)) if matches!(cause.as_ref(),
        Cause::Port(gnunet_client_host::ConnectError::Protocol(Fault::NotReady))))
}
fn get_frame(key: &[u8; 64], options: RouteOptions) -> TestResult<Vec<u8>> {
    let get = GetMessage {
        block_type: 65000,
        options,
        hop_count: 0,
        desired_replication_level: 1,
        peer_bloom: &[255; 128],
        key,
        result_filter: &[],
        extended_query: &[],
    };
    let mut bytes = vec![0; get.encoded_len()?];
    get.encode(&mut bytes)?;
    Ok(bytes)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "This bounded actual CORE Unix and UDP case asserts per-carrier identity gates and original modeled PILS tombstone retirement"
)]
fn changed_pils_keeps_old_core_ordinary_input_but_tracks_only_matching_ip_and_retires_old_signature()
-> TestResult {
    use gnunet_crypto::EddsaPrivateKey;
    use gnunet_wire::official::core::{ClassOrder, PeerClass, PeerId, Request, Response, Traffic};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        timeout(Duration::from_secs(8), async {
            let directory = Directory::new()?;
            let path = directory.0.join("c.sock");
            let listener = tokio::net::UnixListener::bind(&path)?;
            let old_key = EddsaPrivateKey::from_seed([11; 32]);
            let old_local = *old_key.public_key().as_bytes();
            let new_key = EddsaPrivateKey::from_seed([12; 32]);
            let new_local = *new_key.public_key().as_bytes();
            let tracked = get_frame(&[7; 64], RouteOptions::RECORD_ROUTE)?;
            let refused = get_frame(&[8; 64], RouteOptions::RECORD_ROUTE)?;
            let ordinary = get_frame(&[9; 64], RouteOptions::NONE)?;
            let mut actor = Actor(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let mut header = [0; 4]; stream.read_exact(&mut header).await?;
                let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
                if length < 4 { return Err(std::io::Error::other("short actual CORE INIT")); }
                let mut init = vec![0; length]; init[..4].copy_from_slice(&header);
                stream.read_exact(&mut init[4..]).await?;
                if !matches!(Request::decode(&init), Ok(Request::Init { .. })) {
                    return Err(std::io::Error::other("unexpected actual CORE INIT"));
                }
                let order = if cfg!(target_endian = "little") { ClassOrder::Little } else { ClassOrder::Big };
                for response in [Response::InitReply { identity: PeerId(old_local), class: PeerClass::SERVER },
                    Response::Connected { peer: PeerId([2; 32]), class: PeerClass::ROUTER }]
                {
                    let mut output = [0; 128];
                    let length = response.encode(&mut output, order).map_err(std::io::Error::other)?;
                    stream.write_all(&output[..length]).await?;
                }
                for frame in [tracked, refused, ordinary] {
                    let envelope = CoreEnvelope::new(&frame).map_err(std::io::Error::other)?;
                    let mut wire = vec![0; envelope.encoded_len().map_err(std::io::Error::other)?];
                    envelope.encode(&mut wire).map_err(std::io::Error::other)?;
                    let response = Response::Traffic { direction: core::Direction::Inbound,
                        peer: PeerId([2; 32]), traffic: Traffic::Full(&wire) };
                    let mut output = vec![0; 36 + wire.len()];
                    let length = response.encode(&mut output, order).map_err(std::io::Error::other)?;
                    stream.write_all(&output[..length]).await?;
                }
                let mut remaining = [0; 256];
                while stream.read(&mut remaining).await? != 0 {}
                Ok(())
            }));
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let mut instances = Instances::default();
            let mut server = model_server(&mut instances, Some(EndpointSource::unix_with_clock(path, clock)))?;
            let anchor = server.anchor()?;
            server.observe_identity(old_local, anchor)?;
            // Actual INIT_REPLY and Connected mint the CORE source/peer tokens.
            while !server.peers.iter().any(|row| matches!(row.native, NativePeer::Core(_))) {
                core_step(&mut server).await?;
            }
            core_step(&mut server).await?; // first actual tracked GET while identities match
            assert_eq!(server.owner.as_ref().ok_or(Fault::NotReady)?.snapshot().routes, 1);
            let supplier = UdpSocket::bind("127.0.0.1:0").await?;
            let upstream = attach_ip(&mut server, [3; 32], &supplier).await?;
            let now = server.anchor()?;
            let reply = response(&[7; 64], now.now + 5_000_000, b"old captured signer")?;
            server.ingest_native(NativePeer::Ip(upstream), &reply, now, &mut FixedEntropy)?;
            let (job, material) = server.owner.as_ref().ok_or(Fault::NotReady)?.work().find_map(|work| match work {
                Work::Sign { job, material, .. } => Some((job, *material)), _ => None,
            }).ok_or(Fault::NotReady)?;
            // The actual original CORE endpoint is selected before PILS can
            // admit a signature. This fixture has no PILS source authority.
            assert!(sign_not_ready(server.work()));
            assert!(matches!(server.jobs[native_job_index(&server.jobs, job)?].target, Some(NativePeer::Core(_))));
            // The actual pure issued job and real signature model the already
            // authenticated Signer completion boundary; this is not native PILS IO.
            server.owner.as_mut().ok_or(Fault::NotReady)?.sign_started(job)?;
            let captured = &server.jobs[native_job_index(&server.jobs, job)?];
            let original = (captured.bound.until, captured.bound.hard, captured.target);
            let signature = old_key.sign(gnunet_dht::path::PURPOSE, &material)?;
            let changed = server.anchor()?;
            server.observe_identity(new_local, changed)?;
            assert!(!server.closing);
            assert_eq!(server.core.as_ref().ok_or(Fault::NotReady)?.phase.local_identity(), Some(old_local));
            let captured = &server.jobs[native_job_index(&server.jobs, job)?];
            assert_eq!((captured.bound.until, captured.bound.hard, captured.target), original);
            assert!(server.complete_path_signature(job, old_key.public_key(), Ok((old_key.public_key(), signature)))?.is_none());
            assert!(!server.owner.as_ref().ok_or(Fault::NotReady)?.owns_job(job));
            // Same physical CORE MQ: tracked input is rejected as a frame,
            // while the following ordinary GET still creates its real route.
            assert!(matches!(core_step(&mut server).await?, Event::Error { provider: Provider::Core, cause }
                if matches!(cause.as_ref(), Cause::Identity)));
            assert_eq!(server.owner.as_ref().ok_or(Fault::NotReady)?.snapshot().routes, 1);
            assert!(matches!(core_step(&mut server).await?, Event::Activity(Provider::Core)));
            assert_eq!(server.owner.as_ref().ok_or(Fault::NotReady)?.snapshot().routes, 2);
            assert!(!server.closing);
            let event = next(&mut server).await?; // real old IP endpoint retirement
            assert!(matches!(event, crate::ip::Event::Disconnected { peer, .. } if peer == upstream));
            server.ip_event(event)?;
            let downstream = UdpSocket::bind("127.0.0.1:0").await?;
            let matching = attach_ip(&mut server, [2; 32], &downstream).await?;
            let supplier_peer = attach_ip(&mut server, [3; 32], &supplier).await?;
            let now = server.anchor()?;
            let reply = response(&[7; 64], now.now + 5_000_000, b"new captured signer")?;
            server.ingest_native(NativePeer::Ip(supplier_peer), &reply, now, &mut FixedEntropy)?;
            let next_job = server.owner.as_ref().ok_or(Fault::NotReady)?.work().find_map(|work| match work {
                Work::Sign { job, .. } => Some(job), _ => None,
            }).ok_or(Fault::NotReady)?;
            // PILS is intentionally unconnected. Planning freezes the matching
            // IP target before its actual NotReady, skipping the earlier mismatched CORE row.
            assert!(sign_not_ready(server.work()));
            let captured = &server.jobs[native_job_index(&server.jobs, next_job)?];
            assert_eq!(captured.target, Some(NativePeer::Ip(matching)));
            let original = (captured.bound.until, captured.bound.hard, captured.target);
            let now = server.anchor()?; server.sync_jobs(now)?;
            assert!(sign_not_ready(server.work()));
            let captured = &server.jobs[native_job_index(&server.jobs, next_job)?];
            assert_eq!((captured.bound.until, captured.bound.hard, captured.target), original);
            close_model(&mut server).await?;
            timeout(Duration::from_secs(2), &mut actor.0).await???;
            assert!(server.into_report().quiescent);
            Ok::<_, Box<dyn std::error::Error>>(())
        }).await??;
        Ok(())
    })
}
