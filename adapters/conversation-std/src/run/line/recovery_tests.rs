//! Native local-source model, not a normal daemon or C interoperability receipt.
use super::*;
use crate::run::Events;
use gnunet_conversation::{
    crypto::SignedRing,
    wire::{ClientControl, Message, PeerControl},
};
use gnunet_identity::{KeyType, SecretKey};
use gnunet_pils::{HelloLimits, MasterKey, Profile, Service};
use gnunet_service_runtime::{
    clock::SystemClock,
    connection::Connection,
    framing::{Accounting, Budget, Limits as Framing},
    local::{Listener, Stream},
};
use gnunet_wire::official::cadet::{Request, Response};
use std::{
    error::Error as StdError,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

type Failure = Box<dyn StdError>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "cvp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        }
        #[cfg(windows)]
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
async fn write_all(stream: &Stream, bytes: &[u8]) -> io::Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        stream.writable().await?;
        match stream.try_write(&bytes[at..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => at += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
async fn read_exact(stream: &Stream, bytes: &mut [u8]) -> io::Result<()> {
    let mut at = 0;
    while at < bytes.len() {
        stream.readable().await?;
        match stream.try_read(&mut bytes[at..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => at += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
async fn frame(stream: &Stream, mut prefix: Vec<u8>) -> Result<Vec<u8>, Failure> {
    let held = prefix.len();
    if held < 4 {
        prefix.resize(4, 0);
        read_exact(stream, &mut prefix[held..]).await?;
    }
    let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    if !(4..=512).contains(&length) || prefix.len() > length {
        return Err("fixture frame extent".into());
    }
    let held = prefix.len();
    prefix.resize(length, 0);
    read_exact(stream, &mut prefix[held..]).await?;
    Ok(prefix)
}
async fn during<L: Future<Output = LineReport> + ?Sized, A: Future>(
    mut line: Pin<&mut L>,
    action: A,
) -> Result<A::Output, Failure> {
    let mut action = std::pin::pin!(action);
    poll_fn(|cx| {
        if let Poll::Ready(report) = line.as_mut().poll(cx) {
            return Poll::Ready(Err(io::Error::other(format!(
                "Line closed before fixture action: {report:?}"
            ))
            .into()));
        }
        action.as_mut().poll(cx).map(Ok)
    })
    .await
}
fn local(message: Message<'_>) -> Result<Vec<u8>, Failure> {
    let mut bytes = vec![0; 512];
    let n = message.encode(&mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}
fn response(message: Response<'_>) -> Result<Vec<u8>, Failure> {
    let mut bytes = vec![0; 512];
    let n = message.encode(&mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}
fn ring(signed: &SignedRing) -> Result<Vec<u8>, Failure> {
    local(Message::PeerRing {
        reserved: 0,
        expiration: signed.expiration(),
        public_key: signed.public_key(),
        signature: signed.signature(),
    })
}

struct Fixture {
    line: Pin<Box<dyn Future<Output = LineReport>>>,
    frontend: Stream,
    pils_listener: Listener,
    cadet_listener: Listener,
    clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    limits: Limits,
    // Drop the namespace after the original physical owners.
    directory: Directory,
}
async fn fixture() -> Result<Fixture, Failure> {
    fixture_with_limits(Limits::default().peer_input, None).await
}
async fn fixture_with_limits(
    peer_input: Duration,
    payload_budget: Option<usize>,
) -> Result<Fixture, Failure> {
    let directory = Directory::new()?;
    let frontend_listener = Listener::bind(directory.0.join("f"))?;
    let frontend = Stream::connect(directory.0.join("f")).await?;
    let (accepted, _) = frontend_listener.accept().await?;
    let pils_path = directory.0.join("p");
    let cadet_path = directory.0.join("c");
    let pils_listener = Listener::bind(&pils_path)?;
    let cadet_listener = Listener::bind(&cadet_path)?;
    let clock: Arc<dyn gnunet_service_runtime::clock::RuntimeClock> = Arc::new(SystemClock);
    let sources = Sources::new(
        gnunet_client_host::EndpointSource::unix_with_clock(cadet_path, clock.clone()),
        gnunet_client_host::EndpointSource::unix_with_clock(pils_path, clock.clone()),
    )?;
    let mut limits = Limits {
        clients: 1,
        calls: 4,
        frame_bytes: 512,
        io_slice_bytes: 1,
        peer_input,
        core: gnunet_conversation::Limits {
            calls: 4,
            frame_bytes: 500,
            ..Default::default()
        },
        cadet: cadet::Limits {
            frame_bytes: 512,
            io_slice_bytes: 1,
            max_payload_bytes: 500,
            ..Default::default()
        },
        pils: pils::Limits {
            pending_operations: 1,
            frame_bytes: 512,
            io_slice_bytes: 64,
        },
        hello: HelloLimits {
            maximum_input_bytes: 512,
            maximum_address_bytes: 512,
            maximum_addresses: 8,
        },
        ..Default::default()
    };
    if let Some(bytes) = payload_budget {
        limits.core.queued_bytes = limits.core.frame_bytes;
        let mut brand = Instance::new();
        let core = Session::new(&mut brand, Identity::new([1; 32], 1)?, limits.core, 0)?;
        limits.core.retained_bytes = core
            .retained_bytes()?
            .checked_add(bytes)
            .ok_or(Fault::Overflow)?;
    }
    limits.validate()?;
    let io = Framed::new(
        Connection::from_unix(accepted),
        Framing {
            frame_bytes: 512,
            ordinary: Budget {
                frames: 1,
                bytes: 512,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: 1,
        },
    )?;
    let origin = Origin::new(clock.as_ref())?;
    let registry = Rc::new(Registry::new(limits, 0)?);
    let lease = registry.line()?;
    let control = Arc::new(Control::new(0));
    let events = Rc::new(Events::new(16)?);
    let first = origin.after(limits.first_input)?;
    let startup = origin.after(limits.startup)?;
    let line = Box::pin(async move {
        let _lease = lease;
        run(
            io, sources, limits, origin, first, startup, control, registry, events, false,
        )
        .await
    });
    Ok(Fixture {
        line,
        frontend,
        pils_listener,
        cadet_listener,
        clock,
        limits,
        directory,
    })
}

#[test]
fn observer_replacement_freezes_partial_output_and_keeps_calls_on_their_original_cadet_mq()
-> Result<(), Failure> {
    source_recovery(8)
}
#[test]
fn observer_replacement_accepts_the_unchanged_signed_identity_on_a_fresh_epoch()
-> Result<(), Failure> {
    source_recovery(7)
}
#[expect(
    clippy::panic_in_result_fn,
    reason = "Actual native cursors and source recovery are the regression contract"
)]
fn source_recovery(replacement_seed: u8) -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let Fixture { directory: _directory, mut line, frontend, pils_listener, cadet_listener, clock, limits } = fixture().await?;
            let (original_pils, _) = during(line.as_mut(), pils_listener.accept()).await??;
            let now = clock.sample()?.now.as_micros();
            let original = Service::<512>::new(MasterKey::from_seed([7; 32]), Profile::Reference029, now, limits.hello)?;
            let original_peer = *original.identity().public_key().as_bytes();
            during(line.as_mut(), write_all(&original_pils, original.announcement())).await??;
            let port = [9; 64];
            during(line.as_mut(), write_all(&frontend, &local(Message::Register { reserved: 0, port: &port })?)).await??;
            let (cadet_stream, _) = during(line.as_mut(), cadet_listener.accept()).await??;
            let opened = during(line.as_mut(), frame(&cadet_stream, Vec::new())).await??;
            assert!(matches!(Request::decode(&opened)?, Request::PortOpen { port: actual } if actual == port));
            let mut secret = [7; 36];
            secret[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
            let key = SecretKey::new(secret)?;
            let signed = SignedRing::sign(&key, &port, &original_peer, now.checked_add(60_000_000).ok_or(Fault::Overflow)?)?;
            during(line.as_mut(), write_all(&cadet_stream, &response(Response::ChannelCreate {
                channel: 1, peer: [8; 32], port, options: 0,
            })?)).await??;
            during(line.as_mut(), write_all(&cadet_stream, &response(Response::Data {
                channel: 1, priority: 0, messages: &ring(&signed)?,
            })?)).await??;
            let mut first_byte = [0];
            during(line.as_mut(), read_exact(&frontend, &mut first_byte)).await??;
            drop(original_pils);
            let (replacement_pils, _) = during(line.as_mut(), pils_listener.accept()).await??;
            let mut prefix = first_byte.to_vec();
            let mut available = [0; 512];
            match frontend.try_read(&mut available) {
                Ok(n) => prefix.extend_from_slice(&available[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            let expected_length = local(Message::Ring { cid: 0, public_key: signed.public_key() })?.len();
            assert!(prefix.len() < expected_length, "fixture must retain an original partial output");
            for _ in 0..4 {
                during(line.as_mut(), tokio::task::yield_now()).await?;
            }
            assert!(matches!(frontend.try_read(&mut available), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
            let replacement = Service::<512>::new(MasterKey::from_seed([replacement_seed; 32]), Profile::Reference029,
                now, limits.hello)?;
            let next_peer = *replacement.identity().public_key().as_bytes();
            assert_eq!(next_peer == original_peer, replacement_seed == 7);
            if replacement_seed == 7 {
                assert_eq!(replacement.announcement(), original.announcement());
            }
            during(line.as_mut(), write_all(&replacement_pils, replacement.announcement())).await??;
            let first_ring = during(line.as_mut(), frame(&frontend, prefix)).await??;
            let Message::Ring { cid: first_cid, public_key } = Message::decode(&first_ring)? else {
                return Err("original Ring notification missing".into());
            };
            assert_eq!(public_key, signed.public_key());
            let ack = during(line.as_mut(), frame(&cadet_stream, Vec::new())).await??;
            assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 1 }));
            let signed_next = SignedRing::sign(&key, &port, &next_peer, now + 60_000_000)?;
            during(line.as_mut(), write_all(&cadet_stream, &response(Response::ChannelCreate {
                channel: 2, peer: [8; 32], port, options: 0,
            })?)).await??;
            during(line.as_mut(), write_all(&cadet_stream, &response(Response::Data {
                channel: 2, priority: 0, messages: &ring(&signed_next)?,
            })?)).await??;
            let next_ring = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
            assert!(matches!(Message::decode(&next_ring)?, Message::Ring { cid, public_key }
                if cid != first_cid && public_key == signed_next.public_key()));
            let ack = during(line.as_mut(), frame(&cadet_stream, Vec::new())).await??;
            assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 2 }));
            during(line.as_mut(), write_all(&cadet_stream, &response(Response::Ack { channel: 1 })?)).await??;
            during(line.as_mut(), write_all(&frontend, &local(Message::Control {
                action: ClientControl::PickUp, cid: first_cid,
            })?)).await??;
            let pickup = during(line.as_mut(), frame(&cadet_stream, Vec::new())).await??;
            assert!(matches!(Request::decode(&pickup)?, Request::Data { channel: 1, messages, .. }
                if matches!(Message::decode(messages), Ok(Message::PeerControl(PeerControl::PickUp)))));
            drop(frontend);
            let report = line.as_mut().await;
            assert!(report.first_pils_loss.is_some());
            assert_eq!(report.calls_started, 2);
            assert_eq!(report.calls_closed, 2);
            assert!(report.physical_closed && report.cadet_closed && report.pils_closed);
            assert_eq!(report.undrained, 0);
            assert!(report.cleanup.is_none());
            Ok::<_, Failure>(())
        }).await?
    })
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert real MQ replacement, original loss facts and fresh call ownership without audio devices"
)]
fn cadet_replacement_preserves_the_line_and_reannounces_only_the_logical_port()
-> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        for initial_partial in [false, true] {
            tokio::time::timeout(Duration::from_secs(10), async {
            let Fixture { directory: _directory, mut line, frontend, pils_listener, cadet_listener, clock, limits } = fixture().await?;
            let (pils_stream, _) = during(line.as_mut(), pils_listener.accept()).await??;
            let now = clock.sample()?.now.as_micros();
            let producer = Service::<512>::new(MasterKey::from_seed([7; 32]), Profile::Reference029, now, limits.hello)?;
            let peer = *producer.identity().public_key().as_bytes();
            during(line.as_mut(), write_all(&pils_stream, producer.announcement())).await??;
            let port = [9; 64];
            during(line.as_mut(), write_all(&frontend, &local(Message::Register { reserved: 0, port: &port })?)).await??;
            let (original, _) = during(line.as_mut(), cadet_listener.accept()).await??;
            let mut key_bytes = [7; 36];
            key_bytes[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
            let key = SecretKey::new(key_bytes)?;
            let signed = SignedRing::sign(&key, &port, &peer, now + 60_000_000)?;
            let first_cid = if initial_partial {
                during(line.as_mut(), read_exact(&original, &mut [0])).await??;
                None
            } else {
                let opened = during(line.as_mut(), frame(&original, Vec::new())).await??;
                assert!(matches!(Request::decode(&opened)?, Request::PortOpen { port: p } if p == port));
                during(line.as_mut(), write_all(&original, &response(Response::ChannelCreate { channel: 1, peer: [8; 32], port, options: 0 })?)).await??;
                during(line.as_mut(), write_all(&original, &response(Response::Data { channel: 1, priority: 0, messages: &ring(&signed)? })?)).await??;
                let heard = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                let Message::Ring { cid, .. } = Message::decode(&heard)? else { return Err("original Ring missing".into()); };
                let ack = during(line.as_mut(), frame(&original, Vec::new())).await??;
                assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 1 }));
                Some(cid)
            };
            drop(original);
            let (replacement, _) = during(line.as_mut(), cadet_listener.accept()).await??;
            // Lose another real MQ while its automatic announcement is partial.
            during(line.as_mut(), read_exact(&replacement, &mut [0])).await??;
            drop(replacement);
            let (replacement, _) = during(line.as_mut(), cadet_listener.accept()).await??;
            let announced = during(line.as_mut(), frame(&replacement, Vec::new())).await??;
            assert!(matches!(Request::decode(&announced)?, Request::PortOpen { port: p } if p == port));
            if let Some(cid) = first_cid {
                let ended = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                assert!(matches!(Message::decode(&ended)?, Message::Control { action: ClientControl::HangUp, cid: actual } if actual == cid));
            }
            // Reusing the service's numeric channel on the replacement MQ must
            // create a fresh local call rather than resurrect the old CID.
            during(line.as_mut(), write_all(&replacement, &response(Response::ChannelCreate { channel: 1, peer: [8; 32], port, options: 0 })?)).await??;
            during(line.as_mut(), write_all(&replacement, &response(Response::Data { channel: 1, priority: 0, messages: &ring(&signed)? })?)).await??;
            let heard = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
            assert!(matches!(Message::decode(&heard)?, Message::Ring { cid, .. } if Some(cid) != first_cid));
            let ack = during(line.as_mut(), frame(&replacement, Vec::new())).await??;
            assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 1 }));
            drop(frontend);
            let report = line.as_mut().await;
            assert!(report.first_cadet_loss.is_some() && report.first_pils_loss.is_none());
            assert!(report.cleanup.is_none() && report.undrained == 0);
            assert_eq!(report.calls_started, if initial_partial { 1 } else { 2 });
            assert_eq!(report.calls_started, report.calls_closed);
            if initial_partial { assert!(report.effects_lost >= 1); }
            assert!(report.physical_closed && report.cadet_closed && report.pils_closed);
            Ok::<_, Failure>(())
            }).await??;
        }
        Ok(())
    })
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert original CADET EOF, local call retirement and reannounced listening port"
)]
fn partial_cadet_input_deadline_replaces_only_the_cadet_source() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(6), async {
                let Fixture { directory: _directory, mut line, frontend, pils_listener, cadet_listener, clock, limits } =
                    fixture_with_limits(Duration::from_millis(200), None).await?;
                let (pils_stream, _) = during(line.as_mut(), pils_listener.accept()).await??;
                let now = clock.sample()?.now.as_micros();
                let producer = Service::<512>::new(MasterKey::from_seed([7; 32]), Profile::Reference029, now, limits.hello)?;
                let peer = *producer.identity().public_key().as_bytes();
                during(line.as_mut(), write_all(&pils_stream, producer.announcement())).await??;
                let port = [9; 64];
                during(line.as_mut(), write_all(&frontend, &local(Message::Register { reserved: 0, port: &port })?)).await??;
                let (original, _) = during(line.as_mut(), cadet_listener.accept()).await??;
                let opened = during(line.as_mut(), frame(&original, Vec::new())).await??;
                assert!(matches!(Request::decode(&opened)?, Request::PortOpen { port: p } if p == port));

                let mut secret = [7; 36];
                secret[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
                let signed = SignedRing::sign(&SecretKey::new(secret)?, &port, &peer, now + 60_000_000)?;
                let create = response(Response::ChannelCreate { channel: 1, peer: [8; 32], port, options: 0 })?;
                let incoming = response(Response::Data { channel: 1, priority: 0, messages: &ring(&signed)? })?;
                during(line.as_mut(), write_all(&original, &create)).await??;
                during(line.as_mut(), write_all(&original, &incoming)).await??;
                let heard = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                let Message::Ring { cid, .. } = Message::decode(&heard)? else {
                    return Err("missing Ring on original Line".into());
                };
                let ack = during(line.as_mut(), frame(&original, Vec::new())).await??;
                assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 1 }));

                let stalled = response(Response::Data { channel: 1, priority: 0,
                    messages: &local(Message::PeerControl(PeerControl::HangUp))? })?;
                during(line.as_mut(), write_all(&original, &stalled[..3])).await??;
                let ended = during(line.as_mut(), read_exact(&original, &mut [0])).await?;
                assert_eq!(ended.err().map(|error| error.kind()), Some(io::ErrorKind::UnexpectedEof));

                let (replacement, _) = during(line.as_mut(), cadet_listener.accept()).await??;
                let announced = during(line.as_mut(), frame(&replacement, Vec::new())).await??;
                assert!(matches!(Request::decode(&announced)?, Request::PortOpen { port: p } if p == port));
                let hung_up = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                assert!(matches!(Message::decode(&hung_up)?, Message::Control { action: ClientControl::HangUp, cid: actual } if actual == cid));
                during(line.as_mut(), write_all(&replacement, &create)).await??;
                during(line.as_mut(), write_all(&replacement, &incoming)).await??;
                let heard = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                assert!(matches!(Message::decode(&heard)?, Message::Ring { cid: actual, .. } if actual != cid));
                let ack = during(line.as_mut(), frame(&replacement, Vec::new())).await??;
                assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 1 }));

                drop(frontend);
                let report = line.as_mut().await;
                assert!(matches!(report.first_cadet_loss, Some(cadet::LossCause::Requested)));
                assert!(report.first_pils_loss.is_none());
                assert_eq!(report.calls_started, 2);
                assert_eq!(report.calls_closed, 2);
                assert!(report.cleanup.is_none() && report.undrained == 0);
                Ok::<_, Failure>(())
            }).await?
        })
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Verify an original timed-out channel closes without losing another active call"
)]
fn held_cadet_packet_deadline_closes_only_its_original_call() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(6), async {
            let Fixture { directory: _directory, mut line, frontend, pils_listener, cadet_listener, clock, limits } =
                fixture_with_limits(Duration::from_millis(500), Some(128)).await?;
            let (pils_stream, _) = during(line.as_mut(), pils_listener.accept()).await??;
            let now = clock.sample()?.now.as_micros();
            let producer = Service::<512>::new(MasterKey::from_seed([7; 32]), Profile::Reference029, now, limits.hello)?;
            let peer = *producer.identity().public_key().as_bytes();
            during(line.as_mut(), write_all(&pils_stream, producer.announcement())).await??;
            let port = [9; 64];
            let register = local(Message::Register { reserved: 0, port: &port })?;
            during(line.as_mut(), write_all(&frontend, &register)).await??;
            let (native, _) = during(line.as_mut(), cadet_listener.accept()).await??;
            let opened = during(line.as_mut(), frame(&native, Vec::new())).await??;
            assert!(matches!(Request::decode(&opened)?, Request::PortOpen { port: p } if p == port));

            let mut secret = [7; 36];
            secret[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
            let signed = SignedRing::sign(&SecretKey::new(secret)?, &port, &peer, now + 60_000_000)?;
            let ring = ring(&signed)?;
            let mut cids = [0; 2];
            for channel in [1, 2] {
                let create = response(Response::ChannelCreate { channel, peer: [8; 32], port, options: 0 })?;
                let incoming = response(Response::Data { channel, priority: 0, messages: &ring })?;
                during(line.as_mut(), write_all(&native, &create)).await??;
                during(line.as_mut(), write_all(&native, &incoming)).await??;
                let heard = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                let Message::Ring { cid, .. } = Message::decode(&heard)? else {
                    return Err("missing Ring".into());
                };
                cids[usize::try_from(channel)? - 1] = cid;
                let ack = during(line.as_mut(), frame(&native, Vec::new())).await??;
                assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: actual } if actual == channel));
                let credit = response(Response::Ack { channel })?;
                during(line.as_mut(), write_all(&native, &credit)).await??;
                let pickup = local(Message::Control { cid, action: ClientControl::PickUp })?;
                during(line.as_mut(), write_all(&frontend, &pickup)).await??;
                let picked_up = during(line.as_mut(), frame(&native, Vec::new())).await??;
                assert!(matches!(Request::decode(&picked_up)?, Request::Data { channel: actual, messages, .. }
                    if actual == channel && matches!(Message::decode(messages)?, Message::PeerControl(PeerControl::PickUp))));
            }

            let oversized_for_queue = local(Message::PeerAudio(&[0x42; 400]))?;
            let holding = response(Response::Data { channel: 1, priority: 0, messages: &oversized_for_queue })?;
            during(line.as_mut(), write_all(&native, &holding)).await??;
            let retired = during(line.as_mut(), frame(&native, Vec::new())).await??;
            assert!(matches!(Request::decode(&retired)?, Request::ChannelDestroy { channel: 1 }));
            let hangup = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
            assert!(matches!(Message::decode(&hangup)?, Message::Control { cid, action: ClientControl::HangUp } if cid == cids[0]));

            let audio = local(Message::PeerAudio(b"live"))?;
            let next = response(Response::Data { channel: 2, priority: 0, messages: &audio })?;
            during(line.as_mut(), write_all(&native, &next)).await??;
            let heard = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
            assert!(matches!(Message::decode(&heard)?, Message::Audio { cid, data: b"live" } if cid == cids[1]));
            let ack = during(line.as_mut(), frame(&native, Vec::new())).await??;
            assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 2 }));

            drop(frontend);
            let report = line.as_mut().await;
            assert!(report.first_cadet_loss.is_none() && report.first_pils_loss.is_none());
            assert_eq!(report.calls_started, 2);
            assert_eq!(report.calls_closed, 2);
            assert!(report.cleanup.is_none() && report.undrained == 0);
            Ok::<_, Failure>(())
        }).await?
    })
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert original media bytes, actual MQ loss and fresh call ownership without audio devices"
)]
fn active_media_replacement_loses_the_original_prefix_without_replaying_it() -> Result<(), Failure>
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let Fixture {
                    directory: _directory,
                    mut line,
                    frontend,
                    pils_listener,
                    cadet_listener,
                    clock,
                    limits,
                } = fixture().await?;
                let (pils_stream, _) = during(line.as_mut(), pils_listener.accept()).await??;
                let now = clock.sample()?.now.as_micros();
                let producer = Service::<512>::new(
                    MasterKey::from_seed([7; 32]),
                    Profile::Reference029,
                    now,
                    limits.hello,
                )?;
                let peer = *producer.identity().public_key().as_bytes();
                during(line.as_mut(), write_all(&pils_stream, producer.announcement())).await??;
                let port = [9; 64];
                during(
                    line.as_mut(),
                    write_all(&frontend, &local(Message::Register { reserved: 0, port: &port })?),
                ).await??;
                let (original, _) = during(line.as_mut(), cadet_listener.accept()).await??;
                let opened = during(line.as_mut(), frame(&original, Vec::new())).await??;
                assert!(matches!(Request::decode(&opened)?, Request::PortOpen { port: p } if p == port));
                let mut secret = [7; 36];
                secret[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
                let key = SecretKey::new(secret)?;
                let signed = SignedRing::sign(&key, &port, &peer, now + 60_000_000)?;
                during(
                    line.as_mut(),
                    write_all(&original, &response(Response::ChannelCreate { channel: 1, peer: [8; 32], port, options: 0 })?),
                ).await??;
                during(
                    line.as_mut(),
                    write_all(&original, &response(Response::Data { channel: 1, priority: 0, messages: &ring(&signed)? })?),
                ).await??;
                let heard = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                let Message::Ring { cid, .. } = Message::decode(&heard)? else {
                    return Err("original Ring absent".into());
                };
                let ack = during(line.as_mut(), frame(&original, Vec::new())).await??;
                assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 1 }));
                during(line.as_mut(), write_all(&original, &response(Response::Ack { channel: 1 })?)).await??;
                during(
                    line.as_mut(),
                    write_all(&frontend, &local(Message::Control { action: ClientControl::PickUp, cid })?),
                ).await??;
                let pickup = during(line.as_mut(), frame(&original, Vec::new())).await??;
                assert!(matches!(Request::decode(&pickup)?, Request::Data { channel: 1, messages, .. }
                    if matches!(Message::decode(messages)?, Message::PeerControl(PeerControl::PickUp))));
                during(line.as_mut(), write_all(&original, &response(Response::Ack { channel: 1 })?)).await??;

                // Exercise media in both directions on the original active call.
                let incoming = [0x24; 32];
                during(
                    line.as_mut(),
                    write_all(&original, &response(Response::Data { channel: 1, priority: 0, messages: &local(Message::PeerAudio(&incoming))? })?),
                ).await??;
                let audio = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                assert!(matches!(Message::decode(&audio)?, Message::Audio { cid: actual, data }
                    if actual == cid && data == incoming));
                let ack = during(line.as_mut(), frame(&original, Vec::new())).await??;
                assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 1 }));

                let outgoing = [0x42; 400];
                during(line.as_mut(), write_all(&frontend, &local(Message::Audio { cid, data: &outgoing })?)).await??;
                let mut prefix = [0];
                during(line.as_mut(), read_exact(&original, &mut prefix)).await??;
                // One-byte syscall slices retain a real exposed original frame.
                // Closing its MQ must not finish that frame on a fresh source.
                drop(original);

                let (replacement, _) = during(line.as_mut(), cadet_listener.accept()).await??;
                let announced = during(line.as_mut(), frame(&replacement, Vec::new())).await??;
                assert!(matches!(Request::decode(&announced)?, Request::PortOpen { port: p } if p == port));
                let ended = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                assert!(matches!(Message::decode(&ended)?, Message::Control { action: ClientControl::HangUp, cid: actual }
                    if actual == cid));

                // Reusing the numeric channel cannot inherit the retired call,
                // its media, or the original receive/send credit.
                during(
                    line.as_mut(),
                    write_all(&replacement, &response(Response::ChannelCreate { channel: 1, peer: [8; 32], port, options: 0 })?),
                ).await??;
                during(
                    line.as_mut(),
                    write_all(&replacement, &response(Response::Data { channel: 1, priority: 0, messages: &ring(&signed)? })?),
                ).await??;
                let heard = during(line.as_mut(), frame(&frontend, Vec::new())).await??;
                assert!(matches!(Message::decode(&heard)?, Message::Ring { cid: actual, .. } if actual != cid));
                let ack = during(line.as_mut(), frame(&replacement, Vec::new())).await??;
                assert!(matches!(Request::decode(&ack)?, Request::Ack { channel: 1 }));
                drop(frontend);
                let report = line.as_mut().await;
                assert!(report.first_cadet_loss.is_some() && report.first_pils_loss.is_none());
                assert!(report.effects_lost >= 1);
                assert!(report.cleanup.is_none() && report.undrained == 0);
                assert_eq!(report.calls_started, 2);
                assert_eq!(report.calls_closed, 2);
                assert!(report.physical_closed && report.cadet_closed && report.pils_closed);
                Ok::<_, Failure>(())
            }).await?
        })
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert positive original peer prefix, ordered drain and unrelated call admission on the same real MQ"
)]
fn hangup_drains_the_original_peer_prefix_without_replacing_the_line_or_mq() -> Result<(), Failure>
{
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let Fixture { directory: _directory, mut line, frontend, pils_listener, cadet_listener, clock, limits }=fixture().await?;
            let (pils_stream,_)=during(line.as_mut(),pils_listener.accept()).await??;
            let now=clock.sample()?.now.as_micros();
            let producer=Service::<512>::new(MasterKey::from_seed([7;32]),Profile::Reference029,now,limits.hello)?;
            let peer=*producer.identity().public_key().as_bytes();
            during(line.as_mut(),write_all(&pils_stream,producer.announcement())).await??;
            let port=[9;64];
            during(line.as_mut(),write_all(&frontend,&local(Message::Register {reserved:0,port:&port})?)).await??;
            let (cadet_stream,_)=during(line.as_mut(),cadet_listener.accept()).await??;
            let opened=during(line.as_mut(),frame(&cadet_stream,Vec::new())).await??;
            assert!(matches!(Request::decode(&opened)?,Request::PortOpen {port:p} if p==port));
            let mut secret=[7;36];secret[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
            let key=SecretKey::new(secret)?;
            let signed=SignedRing::sign(&key,&port,&peer,now+60_000_000)?;
            during(line.as_mut(),write_all(&cadet_stream,&response(Response::ChannelCreate {channel:1,peer:[8;32],port,options:0})?)).await??;
            during(line.as_mut(),write_all(&cadet_stream,&response(Response::Data {channel:1,priority:0,messages:&ring(&signed)?})?)).await??;
            let heard=during(line.as_mut(),frame(&frontend,Vec::new())).await??;
            let Message::Ring {cid,..}=Message::decode(&heard)? else {return Err("original Ring absent".into())};
            let ack=during(line.as_mut(),frame(&cadet_stream,Vec::new())).await??;
            assert!(matches!(Request::decode(&ack)?,Request::Ack {channel:1}));
            during(line.as_mut(),write_all(&cadet_stream,&response(Response::Ack {channel:1})?)).await??;
            during(line.as_mut(),write_all(&frontend,&local(Message::Control {action:ClientControl::PickUp,cid})?)).await??;
            let pickup=during(line.as_mut(),frame(&cadet_stream,Vec::new())).await??;
            assert!(matches!(Request::decode(&pickup)?,Request::Data {channel:1,messages,..}
                if matches!(Message::decode(messages),Ok(Message::PeerControl(PeerControl::PickUp)))));
            during(line.as_mut(),write_all(&cadet_stream,&response(Response::Ack {channel:1})?)).await??;
            let payload=[0x42;400];
            during(line.as_mut(),write_all(&frontend,&local(Message::Audio {cid,data:&payload})?)).await??;
            let mut prefix=[0];during(line.as_mut(),read_exact(&cadet_stream,&mut prefix)).await??;
            during(line.as_mut(),write_all(&frontend,&local(Message::Control {action:ClientControl::HangUp,cid})?)).await??;
            let original=during(line.as_mut(),frame(&cadet_stream,prefix.to_vec())).await??;
            assert!(matches!(Request::decode(&original)?,Request::Data {channel:1,messages,..}
                if matches!(Message::decode(messages),Ok(Message::PeerAudio(data)) if data==payload)));
            during(line.as_mut(),write_all(&cadet_stream,&response(Response::Ack {channel:1})?)).await??;
            let hangup=during(line.as_mut(),frame(&cadet_stream,Vec::new())).await??;
            assert!(matches!(Request::decode(&hangup)?,Request::Data {channel:1,messages,..}
                if matches!(Message::decode(messages),Ok(Message::PeerControl(PeerControl::HangUp)))));
            let destroy=during(line.as_mut(),frame(&cadet_stream,Vec::new())).await??;
            assert!(matches!(Request::decode(&destroy)?,Request::ChannelDestroy {channel:1}));
            during(line.as_mut(),write_all(&cadet_stream,&response(Response::ChannelCreate {channel:2,peer:[8;32],port,options:0})?)).await??;
            during(line.as_mut(),write_all(&cadet_stream,&response(Response::Data {channel:2,priority:0,messages:&ring(&signed)?})?)).await??;
            let next=during(line.as_mut(),frame(&frontend,Vec::new())).await??;
            assert!(matches!(Message::decode(&next)?,Message::Ring {cid:next,..} if next!=cid));
            let ack=during(line.as_mut(),frame(&cadet_stream,Vec::new())).await??;
            assert!(matches!(Request::decode(&ack)?,Request::Ack {channel:2}));
            drop(frontend);
            let report=line.as_mut().await;
            assert!(report.first_cadet_loss.is_none());
            assert!(report.cleanup.is_none() && report.undrained==0);
            assert_eq!(report.calls_started,2);assert_eq!(report.calls_closed,2);
            Ok::<_,Failure>(())
        }).await?
    })
}
