//! Owned real Unix CORE/PILS/subscriber composition; scripted CORE is not a remote peer.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Real effect witnesses assert actual bytes, signer, native ownership and cleanup."
)]
use gnunet_client_host::{
    EndpointSource,
    resolution::{AddressLookup, ResolutionContext, ResolutionTimer},
};
use gnunet_core_client_host::{ClassOrder, PeerClass, PeerId};
use gnunet_nse::{crypto::WorkBits, owner};
use gnunet_nse_host::{Host, Instances, Limits, Ports, Progress, proof};
use gnunet_pils::{Action, HelloLimits, MasterKey, Profile, Service};
use gnunet_service_runtime::{
    clock::{self, RuntimeClock, SystemClock},
    service::{Listener, ServiceOptions},
};
use gnunet_wire::official::{
    self,
    core::{Request, Response},
    nse,
};
use std::{
    error::Error,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn Error + Send + Sync>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let path = std::env::temp_dir().join(format!(
            "gnrs-nse-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
struct UnixPorts(Arc<dyn RuntimeClock>);
impl ResolutionContext for UnixPorts {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.0.clone()
    }
    fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        Err(io::Error::other(
            "unexpected Resolver lookup on Unix-only sources",
        ))
    }
    fn timer(&self, delay: Duration) -> io::Result<ResolutionTimer> {
        let timer = clock::Deadline::after(self.0.clone(), delay).map_err(io::Error::other)?;
        Ok(Box::pin(
            async move { timer.await.map_err(io::Error::other) },
        ))
    }
}
fn source(path: &std::path::Path, clock: Arc<dyn RuntimeClock>) -> Result<EndpointSource, Failure> {
    use std::os::unix::ffi::OsStrExt;
    let mut cfg = gnunet_config::Configuration::default();
    cfg.set_value(b"service", b"UNIXPATH", Some(path.as_os_str().as_bytes()))?;
    Ok(EndpointSource::configuration(
        cfg,
        b"service",
        Arc::new(UnixPorts(clock)),
    ))
}
async fn frame(stream: &mut UnixStream) -> Result<Option<Vec<u8>>, Failure> {
    let mut h = [0; 4];
    match stream.read_exact(&mut h).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if len < 4 {
        return Err("short native frame".into());
    }
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&h);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(Some(bytes))
}
async fn response(stream: &mut UnixStream, value: Response<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; 256];
    let n = value.encode(&mut bytes, ClassOrder::Little)?;
    for chunk in bytes[..n].chunks(3) {
        stream.write_all(chunk).await?;
    }
    Ok(())
}
fn hello() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 32,
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Loss {
    Core,
    Pils,
}
async fn core_frame(
    stream: &mut UnixStream,
    armed: &AtomicBool,
    cut: &AtomicBool,
) -> Result<Option<Vec<u8>>, Failure> {
    let mut h = [0; 4];
    match stream.read_exact(&mut h).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if len < 4 {
        return Err("short CORE frame".into());
    }
    if armed.load(Ordering::SeqCst)
        && u16::from_be_bytes([h[2], h[3]]) == official::message_type::CORE_SEND.value()
    {
        let mut first = [0; 1];
        stream.read_exact(&mut first).await?;
        cut.store(true, Ordering::SeqCst);
        return Ok(None);
    }
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&h);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(Some(bytes))
}
async fn single_poll_drive<'i>(
    host: &mut Host<'i, 4, 4>,
    listeners: &[Listener<'_>],
    deadline: Instant,
) -> Result<Progress, gnunet_nse_host::Error> {
    use std::{
        future::{Future, poll_fn},
        task::Poll,
    };
    loop {
        // Construct and drop a fresh drive after exactly one poll, like a
        // containing native owner that polls several services per turn.
        let result = poll_fn(|cx| {
            let mut observe = |_| {};
            let driving = host.drive(listeners, &mut observe, Some(deadline));
            let mut driving = std::pin::pin!(driving);
            Poll::Ready(driving.as_mut().poll(cx))
        })
        .await;
        match result {
            Poll::Ready(result) => return result,
            Poll::Pending => tokio::task::yield_now().await,
        }
    }
}
async fn composition(
    bits: u16,
    saved: Option<[u8; 8]>,
    mine_only: bool,
    advance_rounds: bool,
    remote: bool,
    loss: Option<Loss>,
    scheduling_probe: bool,
) -> Result<gnunet_nse_host::Report, Failure> {
    composition_profile(
        (bits, Profile::Reference029),
        saved,
        mine_only,
        advance_rounds,
        remote,
        loss,
        scheduling_probe,
    )
    .await
}
async fn composition_profile(
    (bits, profile): (u16, Profile),
    saved: Option<[u8; 8]>,
    mine_only: bool,
    advance_rounds: bool,
    remote: bool,
    loss: Option<Loss>,
    scheduling_probe: bool,
) -> Result<gnunet_nse_host::Report, Failure> {
    let scratch = Scratch::new()?;
    let shared = Arc::new(gnunet_program_host::shared_clock::SharedClock::native(32)?);
    let clock: Arc<dyn RuntimeClock> = shared.clone();
    let now = clock.sample()?.now.as_micros();
    let mut pils = Service::<4096>::new(MasterKey::from_seed([17; 32]), profile, now, hello())?;
    if profile == Profile::ReferenceDeterministic {
        // A real nonempty address hash distinguishes this signed announcement
        // from default029; an empty HELLO would verify under both profiles.
        let mut block = gnunet_wire::official::pils::PeerUpdate::decode(pils.announcement())?
            .block
            .to_vec();
        block.extend_from_slice(b"gnunet+tcp://127.0.0.1:1234\0");
        let mut input = [0; 4096];
        let len =
            gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut input)?;
        let mut scratch = [0; 4096];
        let mut output = [0; 256];
        assert!(matches!(
            pils.receive(&input[..len], &mut scratch, now, &mut output)?,
            Action::Broadcast {
                identity_changed: true
            }
        ));
    }
    let key = *pils.identity().public_key().as_bytes();
    if let Some(saved) = saved {
        std::fs::write(scratch.0.join("proof"), saved)?;
    }
    let pils_listener = UnixListener::bind(scratch.0.join("pils"))?;
    let core_listener = UnixListener::bind(scratch.0.join("core"))?;
    let nse_listener = UnixListener::bind(scratch.0.join("nse"))?;
    let loss_armed = Arc::new(AtomicBool::new(false));
    let loss_cut = Arc::new(AtomicBool::new(false));
    let pils_armed = loss_armed.clone();
    let pils_cut = loss_cut.clone();
    let pils_task = tokio::spawn(async move {
        let (mut stream, _) = pils_listener.accept().await?;
        stream.write_all(pils.announcement()).await?;
        let mut signed = 0;
        while let Some(bytes) = frame(&mut stream).await? {
            if loss == Some(Loss::Pils) && pils_armed.load(Ordering::SeqCst) {
                pils_cut.store(true, Ordering::SeqCst);
                break;
            }
            let mut scratch = [0; 4096];
            let mut output = [0; 256];
            match pils.receive(
                &bytes,
                &mut scratch,
                SystemClock.sample()?.now.as_micros(),
                &mut output,
            )? {
                Action::Reply {
                    len,
                    crypto_error: None,
                } => {
                    signed += 1;
                    stream.write_all(&output[..len]).await?;
                }
                _ => return Err("PILS action was not an actual successful signature".into()),
            }
        }
        Ok::<_, Failure>(signed)
    });
    let (activated_tx, activated_rx) = tokio::sync::oneshot::channel();
    let mut activated_tx = Some(activated_tx);
    let forwarded = Arc::new(AtomicU64::new(0));
    let forwarded_count = forwarded.clone();
    let remote_key = gnunet_crypto::EddsaPrivateKey::from_seed([0x11; 32]);
    let mut remote_fields = nse::flood::Fields {
        hops: 2,
        timestamp: official::AbsoluteTime::from_micros(
            now / gnunet_nse::history::INTERVAL_MICROS * gnunet_nse::history::INTERVAL_MICROS,
        ),
        matching_bits: 100,
        origin: *remote_key.public_key().as_bytes(),
        proof: [0xf1, 0x30, 0, 0, 0, 0, 0, 0],
        signature: [0; 64],
    };
    let mut signed = [0; nse::flood::SIGNED_LEN];
    remote_fields.encode_signed(&mut signed)?;
    remote_fields.signature = *remote_key
        .sign(nse::flood::SIGNATURE_PURPOSE, &signed)?
        .as_bytes();
    let core_armed = if loss == Some(Loss::Core) {
        loss_armed.clone()
    } else {
        Arc::new(AtomicBool::new(false))
    };
    let core_cut = loss_cut.clone();
    let core_task = tokio::spawn(async move {
        let (mut stream, _) = core_listener.accept().await?;
        let init = frame(&mut stream).await?.ok_or("missing CORE init")?;
        assert!(
            matches!(Request::decode(&init)?,Request::Init{types,..}if types.iter().eq([official::message_type::NSE_P2P_FLOOD.value()]))
        );
        response(
            &mut stream,
            Response::InitReply {
                identity: PeerId(key),
                class: PeerClass::SERVER,
            },
        )
        .await?;
        if remote {
            activated_rx.await?;
            response(
                &mut stream,
                Response::Connected {
                    peer: PeerId(remote_fields.origin),
                    class: PeerClass::ROUTER,
                },
            )
            .await?;
            response(
                &mut stream,
                Response::Connected {
                    peer: PeerId([0xa9; 32]),
                    class: PeerClass::ROUTER,
                },
            )
            .await?;
            let mut remote_bytes = [0; nse::flood::MESSAGE_LEN];
            remote_fields.encode(&mut remote_bytes)?;
            response(
                &mut stream,
                Response::Traffic {
                    direction: official::core::Direction::Inbound,
                    peer: PeerId(remote_fields.origin),
                    traffic: official::core::Traffic::Full(&remote_bytes),
                },
            )
            .await?;
        }
        let mut sends = 0;
        let mut memory = Vec::new();
        memory.try_reserve_exact(gnunet_crypto::pow::MEMORY_BLOCKS)?;
        for _ in 0..gnunet_crypto::pow::MEMORY_BLOCKS {
            memory.push(gnunet_crypto::pow::Block::default());
        }
        while let Some(bytes) = core_frame(&mut stream, &core_armed, &core_cut).await? {
            match Request::decode(&bytes)? {
                Request::SendRequest {
                    peer,
                    size,
                    request_id,
                    ..
                } => {
                    assert!(
                        peer == PeerId(key)
                            || (remote
                                && (peer == PeerId(remote_fields.origin)
                                    || peer == PeerId([0xa9; 32])))
                    );
                    assert_eq!(usize::from(size), nse::flood::MESSAGE_LEN);
                    response(
                        &mut stream,
                        Response::SendReady {
                            peer,
                            size,
                            request_id,
                        },
                    )
                    .await?;
                }
                Request::Send { peer, messages, .. } => {
                    assert!(
                        peer == PeerId(key)
                            || (remote
                                && (peer == PeerId(remote_fields.origin)
                                    || peer == PeerId([0xa9; 32])))
                    );
                    let packet = nse::flood::Message::decode(messages)?.fields()?;
                    if remote && packet.origin == remote_fields.origin {
                        assert_eq!(packet.signature, remote_fields.signature);
                        assert_eq!(packet.proof, remote_fields.proof);
                        assert_eq!(packet.hops, remote_fields.hops + 1);
                        // An older already admitted send may return capacity and
                        // schedule a redundant send toward the origin. This is
                        // not a new signature or a remote delivery receipt.
                        forwarded_count.fetch_add(1, Ordering::SeqCst);
                    } else {
                        assert_eq!(packet.origin, key);
                    }
                    gnunet_nse::crypto::admit(messages, WorkBits::new(bits)?, &mut memory)?;
                    sends += 1;
                    response(
                        &mut stream,
                        Response::Traffic {
                            direction: official::core::Direction::Inbound,
                            peer,
                            traffic: official::core::Traffic::Full(messages),
                        },
                    )
                    .await?;
                }
                _ => return Err("unexpected CORE request".into()),
            }
        }
        Ok::<_, Failure>(sends)
    });
    let subscriber_path = scratch.0.join("nse");
    let estimates = Arc::new(AtomicU64::new(0));
    let estimate_count = estimates.clone();
    let subscriber = tokio::spawn(async move {
        let mut stream = UnixStream::connect(subscriber_path).await?;
        let mut start = [0; 4];
        nse::encode_start(&mut start)?;
        stream.write_all(&start).await?;
        while let Some(bytes) = frame(&mut stream).await? {
            let estimate = nse::Estimate::decode(&bytes)?;
            assert!(estimate.timestamp.as_micros() > 1_000_000_000_000);
            estimate_count.fetch_add(1, Ordering::SeqCst);
            if scheduling_probe {
                break;
            }
        }
        Ok::<_, Failure>(())
    });
    let (mut nse_instance, mut core_instance, mut pils_instance) = (
        owner::Instance::new(),
        gnunet_core_client_host::Instance::new(),
        gnunet_pils::client::Instance::new(),
    );
    let ports = Ports {
        core: source(&scratch.0.join("core"), clock.clone())?,
        pils: source(&scratch.0.join("pils"), clock.clone())?,
        clock,
    };
    let mut host = Host::<4, 4>::new(
        Instances {
            nse: &mut nse_instance,
            core: &mut core_instance,
            pils: &mut pils_instance,
        },
        ports,
        owner::Config {
            work_bits: WorkBits::new(bits)?,
            work_delay_micros: if scheduling_probe { 0 } else { 5000 },
            ..owner::Config::default()
        },
        Limits {
            pils_profile: profile,
            peers: 4,
            subscribers: 4,
            io_slice_bytes: 3,
            ..Limits::default()
        },
        ServiceOptions::default(),
        proof::Store::open(scratch.0.join("proof"))?,
    )?;
    let listeners = [Listener::Unix(&nse_listener)];
    let deadline = Instant::now() + Duration::from_secs(if scheduling_probe { 1 } else { 10 });
    let mut activated = false;
    let mut round_advance = None;
    let mut remote_advanced = false;
    let mut loss_before = None;
    loop {
        let until = deadline.min(Instant::now() + Duration::from_millis(20));
        let progress = if scheduling_probe {
            single_poll_drive(&mut host, &listeners, until).await?
        } else {
            host.drive(&listeners, &mut |_| {}, Some(until)).await?
        };
        if loss.is_some() {
            tokio::task::yield_now().await;
        }
        match progress {
            Progress::Activated(actual) => {
                assert_eq!(actual, key);
                activated = true;
                assert_eq!(host.peer_count(), 1);
                if let Some(signal) = activated_tx.take() {
                    let _sent = signal.send(());
                }
            }
            Progress::WaitDeadline if Instant::now() >= deadline => {
                return Err(format!(
                    "real NSE composition did not progress: {:?}, identity={:?}, peers={}, pending={:?}, now={:?}",
                    host.report(), host.identity(), host.peer_count(), host.pending_effects(), shared.sample()
                )
                .into());
            }
            _ => {}
        }
        let report = host.report();
        if scheduling_probe && report.work_calls >= 4 && estimates.load(Ordering::SeqCst) > 0 {
            break;
        }
        if loss.is_some() && (report.core_losses > 0 || report.pils_losses > 0) {
            assert!(loss_cut.load(Ordering::SeqCst));
            assert_eq!(host.peer_count(), 0);
            let baseline = loss_before.ok_or("loss preceded the original baseline")?;
            if loss == Some(Loss::Core) {
                assert_eq!(report.submissions, baseline);
            } else {
                assert!(report.submissions >= baseline);
            }
            loss_before = Some(report.submissions);
            if loss == Some(Loss::Pils) {
                assert_eq!(host.identity(), None);
            } else {
                assert_eq!(host.identity(), Some(key));
            }
            break;
        }
        if remote && report.remote_claims > 0 && !remote_advanced {
            let interval = gnunet_nse::history::INTERVAL_MICROS;
            let phase = shared.sample()?.now.as_micros() % interval;
            shared.set_offset((interval - 2_000_000) as i64 - phase as i64)?;
            remote_advanced = true;
        }
        if remote
            && report.remote_claims > 0
            && forwarded.load(Ordering::SeqCst) > 0
            && estimates.load(Ordering::SeqCst) > 0
        {
            break;
        }
        if !remote
            && activated
            && estimates.load(Ordering::SeqCst) > 0
            && if mine_only {
                report.proofs > 0 && report.durable > 0 && report.estimates > 0
            } else {
                report.signatures > 0
                    && report.submissions > 0
                    && report.self_updates > 0
                    && report.estimates > 0
            }
        {
            if loss.is_some() {
                if loss_before.is_none() {
                    loss_before = Some(report.submissions);
                    loss_armed.store(true, Ordering::SeqCst);
                    let interval = gnunet_nse::history::INTERVAL_MICROS;
                    let phase = shared.sample()?.now.as_micros() % interval;
                    shared.set_offset((2 * interval - 2_000_000 - phase) as i64)?;
                }
                continue;
            }
            if advance_rounds && round_advance.is_none() {
                round_advance = Some(report.self_updates);
                let interval = gnunet_nse::history::INTERVAL_MICROS;
                let phase = shared.sample()?.now.as_micros() % interval;
                // Move to late in the second new absolute hour, when the normal
                // matching-delay policy has become due; do not lower INTERVAL.
                shared.set_offset((3 * interval - 2_000_000 - phase) as i64)?;
                continue;
            }
            if !advance_rounds
                || (report.rounds >= 2 && round_advance.is_some_and(|n| report.self_updates > n))
            {
                break;
            }
        }
    }
    // Let already admitted original replies/notifications reach a quiet native wait
    // before intentional shutdown, so the fixture does not mistake a valid full-MQ
    // retirement during its next fragmented write for a protocol failure.
    for _ in 0..if scheduling_probe { 0 } else { 1024 } {
        if matches!(
            host.drive(
                &listeners,
                &mut |_| {},
                Some(Instant::now() + Duration::from_millis(20))
            )
            .await?,
            Progress::WaitDeadline
        ) {
            break;
        }
    }
    let report = host.report();
    if loss.is_some() {
        assert_eq!(Some(report.submissions), loss_before);
    }
    host.close()?;
    assert_eq!(shared.listeners()?, 0);
    assert!(matches!(
        host.recover_clock(),
        Err(gnunet_nse_host::Error::Protocol(
            gnunet_types::Error::Closed
        ))
    ));
    assert!(matches!(
        host.recover_backend(),
        Err(gnunet_nse_host::Error::Protocol(
            gnunet_types::Error::Closed
        ))
    ));
    assert_eq!(shared.listeners()?, 0);
    assert!(matches!(
        host.drive(&listeners, &mut |_| {}, None).await?,
        Progress::Closed
    ));
    let signatures = pils_task.await??;
    let submitted = core_task.await??;
    if scheduling_probe {
        assert_eq!(signatures, 0);
        assert_eq!(submitted, 0);
        assert!(report.work_calls >= 4 && report.proofs == 0 && report.estimates > 0);
    } else if mine_only {
        assert_eq!(
            std::fs::read(scratch.0.join("proof"))?,
            32508_u64.to_be_bytes()
        );
        assert_eq!(report.work_calls, 2);
        assert_eq!(report.proofs, 1);
    } else {
        if remote {
            assert!(forwarded.load(Ordering::SeqCst) > 0);
            assert!(report.remote_claims > 0);
        }
        assert!(signatures > 0);
        assert!(submitted > 0);
    }
    subscriber.await??;
    Ok(report)
}
#[test]
fn explicit_work0_native_smoke_checks_real_pils_signer_core_loopback_and_subscriber()
-> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let report = runtime.block_on(tokio::time::timeout(
        Duration::from_secs(15),
        composition(0, None, false, false, false, None, false),
    ))??;
    assert_eq!(report.activations, 1);
    assert!(report.signatures > 0 && report.self_updates > 0 && report.estimates > 0);
    Ok(())
}

#[test]
fn conditional_nonempty_hello_uses_selected_pils_profile_for_actual_native_signatures()
-> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let report = runtime.block_on(tokio::time::timeout(
        Duration::from_secs(15),
        composition_profile(
            (0, Profile::ReferenceDeterministic),
            None,
            false,
            false,
            false,
            None,
            false,
        ),
    ))??;
    assert_eq!(report.activations, 1);
    assert!(report.signatures > 0 && report.self_updates > 0 && report.estimates > 0);
    Ok(())
}

#[test]
fn default15_native_original_signatures_loopback_and_estimates() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let report = runtime.block_on(tokio::time::timeout(
        Duration::from_secs(20),
        composition(
            15,
            Some(32508_u64.to_be_bytes()),
            false,
            false,
            false,
            None,
            false,
        ),
    ))??;
    assert_eq!(report.activations, 1);
    assert_eq!(report.work_calls, 0);
    assert!(report.signatures > 0 && report.submissions > 0 && report.self_updates > 0);
    Ok(())
}
#[test]
fn default15_native_budgeted_discovery_is_durable_and_keeps_ipc_live() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    // This is genuine native work from saved progress immediately before the
    // independently mined first valid candidate; it is not a from-zero host search.
    let report = runtime.block_on(tokio::time::timeout(
        Duration::from_secs(20),
        composition(
            15,
            Some(32507_u64.to_be_bytes()),
            true,
            false,
            false,
            None,
            false,
        ),
    ))??;
    assert_eq!(report.work_calls, 2);
    assert_eq!(report.proofs, 1);
    assert!(report.durable > 0 && report.estimates > 0);
    Ok(())
}

#[test]
fn default15_native_rounds_follow_the_original_adjustable_absolute_clock() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let report = runtime.block_on(tokio::time::timeout(
        Duration::from_secs(20),
        composition(
            15,
            Some(32508_u64.to_be_bytes()),
            false,
            true,
            false,
            None,
            false,
        ),
    ))??;
    assert!(report.rounds >= 2 && report.signatures >= 2 && report.self_updates >= 2);
    Ok(())
}

#[test]
fn default15_remote_origin_signature_is_forwarded_without_local_resigning() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let report = runtime.block_on(tokio::time::timeout(
        Duration::from_secs(20),
        composition(
            15,
            Some(32508_u64.to_be_bytes()),
            false,
            false,
            true,
            None,
            false,
        ),
    ))??;
    assert!(report.remote_claims > 0 && report.submissions > 0);
    Ok(())
}

#[test]
fn canonical_clock_refusal_retains_original_owner_until_explicit_recovery_and_close()
-> Result<(), Failure> {
    use gnunet_service_runtime::clock::{ClockSample, ClockSubscription};
    use gnunet_types::Error as ProtocolError;
    use std::sync::atomic::AtomicBool;
    struct Gate {
        base: Arc<gnunet_program_host::shared_clock::SharedClock>,
        fail: AtomicBool,
        samples: AtomicU64,
    }
    impl RuntimeClock for Gate {
        fn sample(&self) -> Result<ClockSample, ProtocolError> {
            self.samples.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                Err(ProtocolError::Capacity)
            } else {
                RuntimeClock::sample(self.base.as_ref())
            }
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, ProtocolError> {
            RuntimeClock::subscribe(self.base.as_ref())
        }
    }
    // A real reserved SharedClock listener backs every source; this gate refuses
    // sampling before native IO, without substituting another time domain.
    let shared = Arc::new(gnunet_program_host::shared_clock::SharedClock::native(8)?);
    let gate = Arc::new(Gate {
        base: shared.clone(),
        fail: AtomicBool::new(true),
        samples: AtomicU64::new(0),
    });
    let clock: Arc<dyn RuntimeClock> = gate.clone();
    let scratch = Scratch::new()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (mut nse, mut core, mut pils) = (
            owner::Instance::new(),
            gnunet_core_client_host::Instance::new(),
            gnunet_pils::client::Instance::new(),
        );
        let mut host = Host::<2, 2>::new(
            Instances {
                nse: &mut nse,
                core: &mut core,
                pils: &mut pils,
            },
            Ports {
                core: source(&scratch.0.join("missing-core"), clock.clone())?,
                pils: source(&scratch.0.join("missing-pils"), clock.clone())?,
                clock,
            },
            owner::Config::default(),
            Limits {
                peers: 2,
                subscribers: 2,
                ..Limits::default()
            },
            ServiceOptions::default(),
            proof::Store::open(scratch.0.join("proof"))?,
        )?;
        assert_eq!(shared.listeners()?, 3);
        for _ in 0..3 {
            assert!(matches!(
                host.drive(&[], &mut |_| {}, None).await,
                Err(gnunet_nse_host::Error::Clock(ProtocolError::Capacity))
            ));
        }
        assert_eq!(gate.samples.load(Ordering::SeqCst), 1);
        assert_eq!(shared.listeners()?, 3);
        assert_eq!(host.identity(), None);
        gate.fail.store(false, Ordering::SeqCst);
        assert!(matches!(
            host.drive(&[], &mut |_| {}, None).await,
            Err(gnunet_nse_host::Error::Clock(ProtocolError::Capacity))
        ));
        host.recover_clock()?;
        assert_eq!(shared.listeners()?, 3);
        assert!(matches!(
            host.drive(
                &[],
                &mut |_| {},
                Some(Instant::now() + Duration::from_millis(20))
            )
            .await?,
            Progress::Activity | Progress::WaitDeadline
        ));
        host.close()?;
        assert_eq!(shared.listeners()?, 0);
        assert!(matches!(
            host.recover_clock(),
            Err(gnunet_nse_host::Error::Protocol(ProtocolError::Closed))
        ));
        assert_eq!(shared.listeners()?, 0);
        Ok::<_, Failure>(())
    })
}

#[test]
fn default15_partial_original_core_payload_loss_retires_only_original_peer_effects()
-> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let report = runtime.block_on(tokio::time::timeout(
        Duration::from_secs(20),
        composition(
            15,
            Some(32508_u64.to_be_bytes()),
            false,
            false,
            false,
            Some(Loss::Core),
            false,
        ),
    ))??;
    assert!(report.core_losses > 0);
    assert_eq!(report.pils_losses, 0);
    Ok(())
}
#[test]
fn default15_pils_eof_during_original_signature_retires_context_without_replay()
-> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let report = runtime.block_on(tokio::time::timeout(
        Duration::from_secs(20),
        composition(
            15,
            Some(32508_u64.to_be_bytes()),
            false,
            false,
            false,
            Some(Loss::Pils),
            false,
        ),
    ))??;
    assert!(report.pils_losses > 0);
    assert_eq!(report.activations, 1);
    Ok(())
}

fn fixture32(text: &str) -> Result<[u8; 32], Failure> {
    let mut bytes = [0; 32];
    if text.len() != 64 {
        return Err("bad fixed32 fixture".into());
    }
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}
async fn observe_subscriber(
    path: PathBuf,
    count: Arc<AtomicU64>,
    eof: Arc<AtomicBool>,
) -> Result<(), Failure> {
    let mut stream = UnixStream::connect(path).await?;
    let mut start = [0; 4];
    nse::encode_start(&mut start)?;
    stream.write_all(&start).await?;
    while let Some(bytes) = frame(&mut stream).await? {
        nse::Estimate::decode(&bytes)?;
        count.fetch_add(1, Ordering::SeqCst);
    }
    eof.store(true, Ordering::SeqCst);
    Ok(())
}
async fn rotating_composition(backend_failure: bool) -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let shared = Arc::new(gnunet_program_host::shared_clock::SharedClock::native(32)?);
    let clock: Arc<dyn RuntimeClock> = shared.clone();
    let now = clock.sample()?.now.as_micros();
    let mut fixture = include_str!("fixtures/pils-rotation15.txt").lines();
    let ikm = fixture32(fixture.next().ok_or("missing IKM fixture")?)?;
    let expected_new = fixture32(fixture.next().ok_or("missing PID fixture")?)?;
    let mut old_pils = Service::<4096>::new(
        MasterKey::from_seed([17; 32]),
        Profile::Reference029,
        now,
        hello(),
    )?;
    let new_pils = Service::<4096>::new(
        MasterKey::from_seed(ikm),
        Profile::Reference029,
        now,
        hello(),
    )?;
    let old_key = *old_pils.identity().public_key().as_bytes();
    let new_key = *new_pils.identity().public_key().as_bytes();
    assert_eq!(new_key, expected_new);
    assert_ne!(old_key, new_key);
    std::fs::write(scratch.0.join("proof"), 32508_u64.to_be_bytes())?;
    let pils_listener = UnixListener::bind(scratch.0.join("pils"))?;
    let core_listener = UnixListener::bind(scratch.0.join("core"))?;
    let nse_listener = UnixListener::bind(scratch.0.join("nse"))?;
    let armed = Arc::new(AtomicBool::new(false));
    let late = Arc::new(AtomicBool::new(false));
    let pils_armed = armed.clone();
    let late_written = late.clone();
    let pils_task = tokio::spawn(async move {
        let (mut stream, _) = pils_listener.accept().await?;
        stream.write_all(old_pils.announcement()).await?;
        let mut replacement = Some(new_pils);
        let mut signed = [0; 2];
        while let Some(bytes) = frame(&mut stream).await? {
            let rotate = pils_armed.load(Ordering::SeqCst) && replacement.is_some();
            if rotate {
                // Keep the exact original old-identity purpose region, announce
                // a genuinely verified new identity on the same physical MQ,
                // then sign that old snapshot with the new actual PILS key.
                let official::pils::Request::Sign { region, .. } =
                    official::pils::Request::decode(&bytes)?
                else {
                    return Err("rotation did not intercept an original sign lease".into());
                };
                assert_eq!(&region[20..52], &old_key);
                old_pils = replacement.take().ok_or("replacement consumed")?;
                stream.write_all(old_pils.announcement()).await?;
            }
            let mut scratch = [0; 4096];
            let mut output = [0; 256];
            let Action::Reply {
                len,
                crypto_error: None,
            } = old_pils.receive(
                &bytes,
                &mut scratch,
                SystemClock.sample()?.now.as_micros(),
                &mut output,
            )?
            else {
                return Err("PILS failed the actual signature".into());
            };
            if rotate {
                let official::pils::Request::Sign { region, .. } =
                    official::pils::Request::decode(&bytes)?
                else {
                    return Err("missing retained sign region".into());
                };
                let official::pils::Response::Signature {
                    peer, signature, ..
                } = official::pils::Response::decode(&output[..len])?
                else {
                    return Err("missing actual new signer result".into());
                };
                assert_eq!(peer, new_key);
                let signature = gnunet_crypto::EddsaSignature::from_bytes(signature);
                gnunet_crypto::EddsaPublicKey::from_bytes(new_key).verify(
                    nse::flood::SIGNATURE_PURPOSE,
                    region,
                    &signature,
                )?;
                assert!(
                    gnunet_crypto::EddsaPublicKey::from_bytes(old_key)
                        .verify(nse::flood::SIGNATURE_PURPOSE, region, &signature)
                        .is_err()
                );
            }
            signed[usize::from(replacement.is_none())] += 1;
            stream.write_all(&output[..len]).await?;
            if rotate {
                late_written.store(true, Ordering::SeqCst);
            }
        }
        Ok::<_, Failure>(signed)
    });
    let core_task = tokio::spawn(async move {
        let mut counts = [0; 2];
        let mut memory = Vec::new();
        memory.try_reserve_exact(gnunet_crypto::pow::MEMORY_BLOCKS)?;
        for _ in 0..gnunet_crypto::pow::MEMORY_BLOCKS {
            memory.push(gnunet_crypto::pow::Block::default());
        }
        for (epoch, key) in [old_key, if backend_failure { old_key } else { new_key }]
            .into_iter()
            .enumerate()
        {
            let (mut stream, _) = core_listener.accept().await?;
            let init = frame(&mut stream).await?.ok_or("missing epoch INIT")?;
            assert!(matches!(Request::decode(&init)?, Request::Init { .. }));
            response(
                &mut stream,
                Response::InitReply {
                    identity: PeerId(key),
                    class: PeerClass::SERVER,
                },
            )
            .await?;
            while let Some(bytes) = frame(&mut stream).await? {
                match Request::decode(&bytes)? {
                    Request::SendRequest {
                        peer,
                        size,
                        request_id,
                        ..
                    } => {
                        assert_eq!(peer, PeerId(key));
                        response(
                            &mut stream,
                            Response::SendReady {
                                peer,
                                size,
                                request_id,
                            },
                        )
                        .await?;
                    }
                    Request::Send { peer, messages, .. } => {
                        assert_eq!(peer, PeerId(key));
                        assert_eq!(nse::flood::Message::decode(messages)?.fields()?.origin, key);
                        gnunet_nse::crypto::admit(messages, WorkBits::new(15)?, &mut memory)?;
                        counts[epoch] += 1;
                        response(
                            &mut stream,
                            Response::Traffic {
                                direction: official::core::Direction::Inbound,
                                peer,
                                traffic: official::core::Traffic::Full(messages),
                            },
                        )
                        .await?;
                    }
                    _ => return Err("unexpected epoch CORE request".into()),
                }
            }
        }
        Ok::<_, Failure>(counts)
    });
    let old_count = Arc::new(AtomicU64::new(0));
    let old_eof = Arc::new(AtomicBool::new(false));
    let old_subscriber = tokio::spawn(observe_subscriber(
        scratch.0.join("nse"),
        old_count.clone(),
        old_eof.clone(),
    ));
    let new_count = Arc::new(AtomicU64::new(0));
    let new_eof = Arc::new(AtomicBool::new(false));
    let mut new_subscriber = None;
    let (mut nse_instance, mut core_instance, mut pils_instance) = (
        owner::Instance::new(),
        gnunet_core_client_host::Instance::new(),
        gnunet_pils::client::Instance::new(),
    );
    let mut host = Host::<4, 4>::new(
        Instances {
            nse: &mut nse_instance,
            core: &mut core_instance,
            pils: &mut pils_instance,
        },
        Ports {
            core: source(&scratch.0.join("core"), clock.clone())?,
            pils: source(&scratch.0.join("pils"), clock.clone())?,
            clock,
        },
        owner::Config::default(),
        Limits {
            peers: 4,
            subscribers: 4,
            io_slice_bytes: 3,
            ..Limits::default()
        },
        ServiceOptions::default(),
        proof::Store::open(scratch.0.join("proof"))?,
    )?;
    let listeners = [Listener::Unix(&nse_listener)];
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut retired = false;
    let mut initial_submissions = None;
    let mut backend_recovered = false;
    loop {
        let result = host
            .drive(
                &listeners,
                &mut |_| {},
                Some(deadline.min(Instant::now() + Duration::from_millis(20))),
            )
            .await;
        tokio::task::yield_now().await;
        let progress = match result {
            Err(gnunet_nse_host::Error::Backend(error)) if backend_failure => {
                assert!(!backend_recovered);
                assert_eq!(error.stage, proof::Stage::Fence);
                assert_eq!(error.outcome, proof::Outcome::Unknown);
                assert_eq!(host.identity(), None);
                assert_eq!(host.peer_count(), 0);
                for _ in 0..3 {
                    assert!(matches!(
                        host.drive(&listeners, &mut |_| {}, None).await?,
                        Progress::BackendQuiescent
                    ));
                }
                assert!(host.recover_backend().is_err());
                std::fs::remove_file(scratch.0.join("proof.nse-lock"))?;
                std::fs::rename(
                    scratch.0.join("original-lock"),
                    scratch.0.join("proof.nse-lock"),
                )?;
                assert_eq!(
                    std::fs::read(scratch.0.join("proof"))?,
                    32508_u64.to_be_bytes()
                );
                host.recover_backend()?;
                backend_recovered = true;
                retired = true;
                continue;
            }
            other => other?,
        };
        match progress {
            Progress::Activated(key) if host.report().activations == 1 => assert_eq!(key, old_key),
            Progress::Activated(key) => {
                assert_eq!(key, if backend_failure { old_key } else { new_key });
                assert!(retired);
                assert_eq!(host.report().activations, 2);
                assert_eq!(host.peer_count(), 1);
                new_subscriber = Some(tokio::spawn(observe_subscriber(scratch.0.join("nse"), new_count.clone(), new_eof.clone())));
            }
            Progress::Retired => { retired = true; assert_eq!(host.identity(), None); assert_eq!(host.peer_count(), 0); }
            Progress::WaitDeadline if Instant::now() >= deadline => return Err(format!("rotation stalled: {:?}, identity={:?}, effects={:?}, late={}, old_eof={}, new_count={}", host.report(), host.identity(), host.pending_effects(), late.load(Ordering::SeqCst), old_eof.load(Ordering::SeqCst), new_count.load(Ordering::SeqCst)).into()),
            _ => {}
        }
        let report = host.report();
        if initial_submissions.is_none()
            && report.self_updates > 0
            && old_count.load(Ordering::SeqCst) > 0
        {
            initial_submissions = Some(report.submissions);
            if backend_failure {
                std::fs::rename(
                    scratch.0.join("proof.nse-lock"),
                    scratch.0.join("original-lock"),
                )?;
                std::fs::write(scratch.0.join("proof.nse-lock"), b"replacement guard")?;
            } else {
                armed.store(true, Ordering::SeqCst);
            }
            let interval = gnunet_nse::history::INTERVAL_MICROS;
            let phase = shared.sample()?.now.as_micros() % interval;
            shared.set_offset((2 * interval - 2_000_000 - phase) as i64)?;
        }
        if report.activations == 2
            && report.self_updates > 1
            && report.submissions > initial_submissions.unwrap_or(u64::MAX)
            && (backend_failure || late.load(Ordering::SeqCst))
            && old_eof.load(Ordering::SeqCst)
            && new_count.load(Ordering::SeqCst) > 0
        {
            break;
        }
    }
    for _ in 0..1024 {
        if matches!(
            host.drive(
                &listeners,
                &mut |_| {},
                Some(Instant::now() + Duration::from_millis(20))
            )
            .await?,
            Progress::WaitDeadline
        ) {
            break;
        }
    }
    let report = host.report();
    assert_eq!(report.activations, 2);
    assert_eq!(report.work_calls, 0);
    assert_eq!(
        host.identity(),
        Some(if backend_failure { old_key } else { new_key })
    );
    host.close()?;
    assert_eq!(shared.listeners()?, 0);
    let signs = pils_task.await??;
    let sends = core_task.await??;
    if backend_failure {
        assert!(backend_recovered);
        assert!(signs[0] > 1 && signs[1] == 0);
    } else {
        assert!(signs[0] > 0 && signs[1] > 1);
    }
    assert!(sends[0] > 0 && sends[1] > 0);
    old_subscriber.await??;
    new_subscriber.ok_or("missing new subscriber")?.await??;
    assert!(new_eof.load(Ordering::SeqCst));
    assert_eq!(
        std::fs::read(scratch.0.join("proof"))?,
        32508_u64.to_be_bytes()
    );
    Ok(())
}
#[test]
fn default15_verified_rotation_retires_old_snapshot_mq_and_subscriber() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(
        Duration::from_secs(20),
        rotating_composition(false),
    ))??;
    Ok(())
}

#[test]
fn default15_active_backend_fence_loss_retires_physical_outputs_until_original_recovery()
-> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(
        Duration::from_secs(20),
        rotating_composition(true),
    ))??;
    Ok(())
}

#[test]
fn default15_zero_delay_single_poll_drops_preserve_yield_progress_and_reactor()
-> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    // Explicit zero work delay stresses scheduling only; accepted default15
    // proofs and production INTERVAL/WORKDELAY settings are unchanged.
    runtime.block_on(tokio::time::timeout(
        Duration::from_secs(5),
        composition(15, None, false, false, false, None, true),
    ))??;
    Ok(())
}
