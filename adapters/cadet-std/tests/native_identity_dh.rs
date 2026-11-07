//! Actual native PILS IO with the real Rust standard-profile PILS Service.
//! Pure Book receipts mint controller request capabilities; this is a provider
//! test, not native CORE or official C tunnel interoperability acceptance.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible provider models assert actual source/operation/hash/retirement observations without formatting secrets"
)]
use gnunet_cadet::{
    connection::{
        self, Authentication, Book, FrameSlot, Neighbor, NeighborSlot, OriginSlot, RouteSlot,
    },
    tunnel::{
        self, SkippedSlot, Storage, context,
        controller::{Controller, Stores},
        identity_dh::{self as pure, Port as DhPort},
    },
};
use gnunet_cadet_host::{
    identity_dh::{Connecting, ContextSlot, JobSlot, Step},
    time::Timebase,
};
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_pils::{Action, HelloLimits, MasterKey, Profile, Service, client::Instance};
use gnunet_pils_host::client::{self as native, EndpointSource, Progress};
use gnunet_session_crypto::exchange::EcdheSecret;
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::cadet_peer::{PathPeers, PeerMessage};
use std::{
    error::Error as StdError,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
use zeroize::Zeroizing;
type Failure = Box<dyn StdError + Send + Sync>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket(PathBuf);
impl Socket {
    fn new() -> Result<(Self, UnixListener), Failure> {
        let p = std::env::temp_dir().join(format!(
            "gnrs-cadet-dh-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let l = UnixListener::bind(&p)?;
        Ok((Self(p), l))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}
fn hello() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 32,
    }
}
fn service() -> Result<Service<4096>, Error> {
    Service::new(
        MasterKey::from_seed([17; 32]),
        Profile::Reference029,
        gnunet_service_runtime::clock::SystemClock
            .sample()?
            .now
            .as_micros(),
        hello(),
    )
}
use gnunet_service_runtime::clock::RuntimeClock;
async fn frame(stream: &mut UnixStream) -> Result<Option<Vec<u8>>, Failure> {
    let mut head = [0; 4];
    let n = stream.read(&mut head[..1]).await?;
    if n == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut head[1..]).await?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if size < 4 {
        return Err("short PILS fixture frame".into());
    }
    let mut out = vec![0; size];
    out[..4].copy_from_slice(&head);
    stream.read_exact(&mut out[4..]).await?;
    Ok(Some(out))
}
async fn reply(
    service: &mut Service<4096>,
    stream: &mut UnixStream,
    request: &[u8],
) -> Result<(), Failure> {
    let mut out = Zeroizing::new([0; 104]);
    let action = service.receive(
        request,
        &mut [],
        gnunet_service_runtime::clock::SystemClock
            .sample()?
            .now
            .as_micros(),
        &mut *out,
    )?;
    let Action::Reply {
        len: 72,
        crypto_error: None,
    } = action
    else {
        return Err("PILS ECDH did not produce its actual standard reply".into());
    };
    stream.write_all(&out[..72]).await?;
    Ok(())
}
struct Draw(u8);
impl Entropy for Draw {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(self.0);
        self.0 = self.0.checked_add(1).ok_or(Error::Entropy)?;
        Ok(())
    }
}
struct Crypto {
    a: [SkippedSlot; 2],
    b: [SkippedSlot; 2],
    c: [SkippedSlot; 2],
    d: [SkippedSlot; 2],
}
impl Crypto {
    fn new() -> Self {
        Self {
            a: [const { SkippedSlot::new() }; 2],
            b: [const { SkippedSlot::new() }; 2],
            c: [const { SkippedSlot::new() }; 2],
            d: [const { SkippedSlot::new() }; 2],
        }
    }
    fn stores(&mut self) -> Stores<'_> {
        Stores {
            first: Storage {
                skipped: &mut self.a,
                staging: &mut self.b,
            },
            second: Storage {
                skipped: &mut self.c,
                staging: &mut self.d,
            },
        }
    }
}
fn setup<'book>(
    book: &mut Book<'book, '_, '_, 4>,
    local: [u8; 32],
    remote: [u8; 32],
    now: MonoInstant,
) -> Result<Neighbor<'book>, Error> {
    let n = book.neighbor_up(remote)?;
    book.neighbor_ready(n, true)?;
    let path = if local < remote {
        [local, remote]
    } else {
        [remote, local]
    };
    if local < remote {
        book.open(
            PathPeers::new(&path),
            [9; 32],
            Authentication::Unsigned,
            now,
        )?;
    } else {
        book.receive(
            n,
            PeerMessage::ConnectionCreate {
                options_bytes: [2, 0, 0, 0],
                has_monotime_bytes: [0; 4],
                monotime: 0,
                monotime_signature: [0; 64],
                connection: [9; 32],
                path: PathPeers::new(&path),
            },
            now,
        )?;
    }
    // Modeled pure CORE boundary only: the native component under test is PILS.
    let frame = book.next_frame().ok_or(Error::NotReady)?.frame;
    let op = book.start(frame)?;
    book.exposed(op)?;
    book.settle(op, true, now)?;
    book.release_frame(frame)?;
    if local < remote {
        book.receive(
            n,
            PeerMessage::ConnectionCreateAck {
                reserved: 0,
                connection: [9; 32],
            },
            now,
        )?;
    }
    Ok(n)
}
fn mint<'id, 'book>(
    controller: &mut Controller<'id, '_, 'book>,
    book: &mut Book<'book, '_, '_, 4>,
    neighbor: Neighbor<'book>,
    remote: &EcdheSecret,
    now: MonoInstant,
    draw: &mut Draw,
) -> Result<pure::Request<'id>, Error> {
    let ratchet = EcdheSecret::from_bytes([99; 32]);
    let message = if controller.scope().local() < controller.scope().peer() {
        controller.request(controller.scope(), now, draw)?;
        PeerMessage::KeyExchangeAuth {
            connection: [9; 32],
            flags: 0,
            ephemeral_key: *remote.public_key().as_bytes(),
            ratchet_key: *ratchet.public_key().as_bytes(),
            auth: [0; 64],
        }
    } else {
        PeerMessage::KeyExchange {
            connection: [9; 32],
            flags: 1,
            ephemeral_key: *remote.public_key().as_bytes(),
            ratchet_key: *ratchet.public_key().as_bytes(),
        }
    };
    let connection::Event::Endpoint(input) = book.receive(neighbor, message, now)? else {
        return Err(Error::Malformed);
    };
    controller.control(controller.scope(), input, now, draw)?;
    controller.pending_identity_dh().ok_or(Error::NotReady)
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

#[test]
fn one_actual_source_serves_two_contexts_reuses_high_water_and_stops_without_replay_on_loss()
-> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(8), async {
        let (socket, listener) = Socket::new()?;
        let mut svc = service()?;
        let local = *svc.identity().public_key().as_bytes();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(svc.announcement()).await?;
            let mut count = 0;
            while let Some(request) = frame(&mut stream).await? {
                count += 1;
                if count == 4 {
                    break;
                }
                reply(&mut svc, &mut stream, &request).await?;
            }
            Ok::<_, Failure>(count)
        });
        let peer1 = *EddsaPrivateKey::from_seed([1; 32]).public_key().as_bytes();
        let peer2 = *EddsaPrivateKey::from_seed([2; 32]).public_key().as_bytes();
        let domain = context::Instance::new();
        let mut context_rows = [const { context::Slot::new() }; 2];
        let mut registry = context::Registry::new(&domain, &mut context_rows)?;
        let context1 = registry.allocate(local, peer1)?;
        let context2 = registry.allocate(local, peer2)?;
        let mut instance = Instance::new();
        let source_domain = pure::Instance::new();
        let mut source_rows = [const { pure::Slot::new() }; 1];
        let mut source_registry = pure::Registry::new(&source_domain, &mut source_rows)?;
        let mut jobs = [const { JobSlot::new() }; 2];
        let mut contexts = [ContextSlot::new(); 2];
        let mut startup = Connecting::<4>::new(
            &mut instance,
            EndpointSource::unix(socket.0.clone()),
            local,
            Profile::Reference029,
            native::Limits {
                pending_operations: 4,
                ..native::Limits::default()
            },
            hello(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(6);
        let actual_identity = loop {
            match startup.drive(Some(deadline)).await? {
                Progress::Inbound(gnunet_pils::client::Inbound::Identity { identity, .. }) => {
                    break identity;
                }
                Progress::WaitDeadline => return Err("actual PILS identity timeout".into()),
                _ => {}
            }
        };
        let timebase = Timebase::new(startup.clock())?;
        let mut port = startup
            .bind(&mut source_registry, &mut jobs, &mut contexts, timebase)
            .map_err(|r| r.reason)?;
        assert_eq!(port.source().epoch(), actual_identity.epoch().value());
        assert_eq!(port.source().local(), local);
        let now = port.timebase().sample()?.monotonic;
        let mut bi1 = connection::Instance::new();
        let mut ns1 = [NeighborSlot::new(); 2];
        let mut rs1 = [RouteSlot::<4>::new(); 2];
        let mut os1 = [OriginSlot::new(); 1];
        let mut buf1 = [[0; 512]; 2];
        let mut fs1 = buf1.each_mut().map(|b| FrameSlot::new(b));
        let mut book1 = Book::new(
            &mut bi1,
            local,
            &mut ns1,
            &mut rs1,
            &mut os1,
            &mut fs1,
            now,
            connection::Limits::default(),
        )?;
        let mut bi2 = connection::Instance::new();
        let mut ns2 = [NeighborSlot::new(); 2];
        let mut rs2 = [RouteSlot::<4>::new(); 2];
        let mut os2 = [OriginSlot::new(); 1];
        let mut buf2 = [[0; 512]; 2];
        let mut fs2 = buf2.each_mut().map(|b| FrameSlot::new(b));
        let mut book2 = Book::new(
            &mut bi2,
            local,
            &mut ns2,
            &mut rs2,
            &mut os2,
            &mut fs2,
            now,
            connection::Limits::default(),
        )?;
        let n1 = setup(&mut book1, local, peer1, now)?;
        let n2 = setup(&mut book2, local, peer2, now)?;
        let mut slots1 = Crypto::new();
        let mut slots2 = Crypto::new();
        let mut c1 = Controller::new_external_identity(
            context1,
            port.source(),
            book1.reset_authority(),
            slots1.stores(),
            tunnel::controller::Limits::default(),
            now,
        )?;
        let mut c2 = Controller::new_external_identity(
            context2,
            port.source(),
            book2.reset_authority(),
            slots2.stores(),
            tunnel::controller::Limits::default(),
            now,
        )?;
        let remote1 = EcdheSecret::from_bytes([40; 32]);
        let remote2 = EcdheSecret::from_bytes([41; 32]);
        let mut draw = Draw(10);
        let r1 = mint(&mut c1, &mut book1, n1, &remote1, now, &mut draw)?;
        let r2 = mint(&mut c2, &mut book2, n2, &remote2, now, &mut draw)?;
        assert_eq!(r1.generation().value(), r2.generation().value());
        assert!(!r1.generation().same_context(r2.generation()));
        port.submit(r1)?;
        port.submit(r2)?;
        let (mut got1, mut got2) = (false, false);
        while !(got1 && got2) {
            match port.drive(Some(deadline)).await? {
                Step::Result { request, .. } => {
                    got1 |= request == r1;
                    got2 |= request == r2;
                }
                Step::Native(Progress::WaitDeadline) => {
                    return Err("actual DH results timeout".into());
                }
                Step::Lost { .. } | Step::Closed(_) => {
                    return Err("PILS stopped before actual result".into());
                }
                _ => {}
            }
        }
        let expected1 = remote1.exchange_edwards_hashed(&local)?.into_secret_bytes();
        let expected2 = remote2.exchange_edwards_hashed(&local)?.into_secret_bytes();
        assert!(matches!(
            port.finish(r2, |bytes| if bytes == &*expected2 {
                Ok(())
            } else {
                Err(Error::Authentication)
            })?,
            pure::Completion::Finished(Ok(()))
        ));
        assert!(matches!(
            port.finish(r1, |bytes| if bytes == &*expected1 {
                Ok(())
            } else {
                Err(Error::Authentication)
            })?,
            pure::Completion::Finished(Ok(()))
        ));
        assert_eq!(port.submit(r1), Err(Error::Conflict));
        assert_eq!(port.submit(r2), Err(Error::Conflict));
        // Provider API was exercised directly; clear the pure queued capability
        // only after the actual backend result was already consumed/settled.
        c1.retire_identity_dh(c1.scope(), &mut port)?;
        let remote3 = EcdheSecret::from_bytes([42; 32]);
        let now = port.timebase().sample()?.monotonic;
        let r3 = mint(&mut c1, &mut book1, n1, &remote3, now, &mut draw)?;
        assert!(r3.generation().same_context(r1.generation()));
        assert!(r3.generation().value() > r1.generation().value());
        port.submit(r3)?;
        loop {
            match port.drive(Some(deadline)).await? {
                Step::Result { request, .. } if request == r3 => break,
                Step::Native(Progress::WaitDeadline) => {
                    return Err("next original generation stalled behind ledger".into());
                }
                _ => {}
            }
        }
        let expected3 = remote3.exchange_edwards_hashed(&local)?.into_secret_bytes();
        assert!(matches!(
            port.finish(r3, |b| if b == &*expected3 {
                Ok(())
            } else {
                Err(Error::Authentication)
            })?,
            pure::Completion::Finished(Ok(()))
        ));
        // Retiring the original candidate revoked its admission before the
        // replacement generation; the old copy is stale even with a ledger.
        assert_eq!(port.submit(r1), Err(Error::StaleGeneration));
        assert_eq!(port.report().consumed, 3);
        c1.retire_identity_dh(c1.scope(), &mut port)?;
        let remote4 = EcdheSecret::from_bytes([43; 32]);
        let now = port.timebase().sample()?.monotonic;
        let r4 = mint(&mut c1, &mut book1, n1, &remote4, now, &mut draw)?;
        port.submit(r4)?;
        loop {
            match port.drive(Some(deadline)).await? {
                Step::Lost { .. } => break,
                Step::Native(Progress::WaitDeadline) => {
                    return Err("original MQ EOF did not retire provider".into());
                }
                _ => {}
            }
        }
        let mut called = false;
        assert!(matches!(
            port.finish(r4, |_| {
                called = true;
                Ok(())
            })?,
            pure::Completion::Finished(Err(Error::Closed))
        ));
        assert!(!called);
        assert_eq!(port.submit(r4), Err(Error::Closed));
        assert!(matches!(
            port.drive(Some(deadline)).await?,
            Step::Closed(Error::Closed)
        ));
        assert_eq!(port.report().stopped, 1);
        assert_eq!(server.await??, 4);
        let _retired = port.close();
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn cancel_partial_original_drains_same_mq_and_late_result_cannot_complete_next_request()
-> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(8), async {
        let (socket, listener) = Socket::new()?;
        let mut svc = service()?;
        let local = *svc.identity().public_key().as_bytes();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(svc.announcement()).await?;
            let mut count = 0;
            while let Some(request) = frame(&mut stream).await? {
                count += 1;
                reply(&mut svc, &mut stream, &request).await?;
            }
            Ok::<_, Failure>(count)
        });
        let peer = *EddsaPrivateKey::from_seed([1; 32]).public_key().as_bytes();
        let domain = context::Instance::new();
        let mut context_rows = [const { context::Slot::new() }; 1];
        let mut registry = context::Registry::new(&domain, &mut context_rows)?;
        let context = registry.allocate(local, peer)?;
        let mut instance = Instance::new();
        let source_domain = pure::Instance::new();
        let mut source_rows = [const { pure::Slot::new() }; 1];
        let mut source_registry = pure::Registry::new(&source_domain, &mut source_rows)?;
        let mut jobs = [const { JobSlot::new() }; 1];
        let mut contexts = [ContextSlot::new(); 1];
        let mut startup = Connecting::<4>::new(
            &mut instance,
            EndpointSource::unix(socket.0.clone()),
            local,
            Profile::Reference029,
            native::Limits {
                pending_operations: 4,
                io_slice_bytes: 1,
                ..native::Limits::default()
            },
            hello(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            match startup.drive(Some(deadline)).await? {
                Progress::Inbound(gnunet_pils::client::Inbound::Identity { .. }) => break,
                Progress::WaitDeadline => return Err("startup timeout".into()),
                _ => {}
            }
        }
        let timebase = Timebase::new(startup.clock())?;
        let mut port = startup
            .bind(&mut source_registry, &mut jobs, &mut contexts, timebase)
            .map_err(|r| r.reason)?;
        let source = port.source();
        let now = port.timebase().sample()?.monotonic;
        let mut bi = connection::Instance::new();
        let mut ns = [NeighborSlot::new(); 2];
        let mut rs = [RouteSlot::<4>::new(); 2];
        let mut os = [OriginSlot::new(); 1];
        let mut buf = [[0; 512]; 2];
        let mut fs = buf.each_mut().map(|b| FrameSlot::new(b));
        let mut book = Book::new(
            &mut bi,
            local,
            &mut ns,
            &mut rs,
            &mut os,
            &mut fs,
            now,
            connection::Limits::default(),
        )?;
        let neighbor = setup(&mut book, local, peer, now)?;
        let mut slots = Crypto::new();
        let mut controller = Controller::new_external_identity(
            context,
            port.source(),
            book.reset_authority(),
            slots.stores(),
            tunnel::controller::Limits::default(),
            now,
        )?;
        let remote = EcdheSecret::from_bytes([50; 32]);
        let mut draw = Draw(10);
        let original = mint(
            &mut controller,
            &mut book,
            neighbor,
            &remote,
            now,
            &mut draw,
        )?;
        port.submit(original)?;
        loop {
            match port.drive(Some(deadline)).await? {
                Step::Native(Progress::Activity {
                    written_bytes: 1, ..
                }) => break,
                Step::Native(Progress::WaitDeadline) => {
                    return Err("partial request never wrote".into());
                }
                _ => {}
            }
        }
        assert!(!port.retire(original)?);
        loop {
            match port.drive(Some(deadline)).await? {
                Step::Retired { request, .. } if request == original => break,
                Step::Native(Progress::WaitDeadline) => {
                    return Err("original cancelled prefix did not physically drain".into());
                }
                _ => {}
            }
        }
        assert!(port.retire(original)?);
        assert_eq!(port.source(), source);
        assert_eq!(port.submit(original), Err(Error::Conflict));
        controller.retire_identity_dh(controller.scope(), &mut port)?;
        let remote2 = EcdheSecret::from_bytes([51; 32]);
        let now = port.timebase().sample()?.monotonic;
        let next = mint(
            &mut controller,
            &mut book,
            neighbor,
            &remote2,
            now,
            &mut draw,
        )?;
        port.submit(next)?;
        loop {
            match port.drive(Some(deadline)).await? {
                Step::Result { request, .. } if request == next => break,
                Step::Result { .. } => {
                    return Err("old cancelled result acquired new authority".into());
                }
                Step::Native(Progress::WaitDeadline) => return Err("new result timeout".into()),
                _ => {}
            }
        }
        let expected = remote2.exchange_edwards_hashed(&local)?.into_secret_bytes();
        assert!(matches!(
            port.finish(next, |b| if b == &*expected {
                Ok(())
            } else {
                Err(Error::Authentication)
            })?,
            pure::Completion::Finished(Ok(()))
        ));
        assert_eq!(port.report().received, 1);
        let _retired = port.close();
        assert_eq!(server.await??, 2);
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

// Append to the migrated adapters/cadet-std/tests/native_identity_dh.rs.
// Reuses its actual Service/socket helpers. CORE authorization remains modeled.
#[test]
fn closed_unsubmitted_context_cannot_reissue_and_one_slot_serves_new_peers_on_one_mq()
-> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(8), async {
        let (socket, listener) = Socket::new()?;
        let mut svc = service()?;
        let local = *svc.identity().public_key().as_bytes();
        let server = tokio::spawn(async move {
            // Exactly one real shared MQ serves all successful allocations.
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(svc.announcement()).await?;
            let mut count = 0;
            while let Some(request) = frame(&mut stream).await? {
                count += 1;
                reply(&mut svc, &mut stream, &request).await?;
            }
            Ok::<_, Failure>(count)
        });
        let domain = context::Instance::new();
        let mut context_rows = [const { context::Slot::new() }; 1];
        let mut registry = context::Registry::new(&domain, &mut context_rows)?;
        let source_domain = pure::Instance::new();
        let mut source_rows = [const { pure::Slot::new() }; 1];
        let mut source_registry = pure::Registry::new(&source_domain, &mut source_rows)?;
        let mut instance = Instance::new();
        let mut jobs = [const { JobSlot::new() }; 1];
        let mut contexts = [ContextSlot::new(); 1];
        let mut startup = Connecting::<4>::new(
            &mut instance,
            EndpointSource::unix(socket.0.clone()),
            local,
            Profile::Reference029,
            native::Limits {
                pending_operations: 4,
                io_slice_bytes: 1,
                ..native::Limits::default()
            },
            hello(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            match startup.drive(Some(deadline)).await? {
                Progress::Inbound(gnunet_pils::client::Inbound::Identity { .. }) => break,
                Progress::WaitDeadline => return Err("startup timeout".into()),
                _ => {}
            }
        }
        let timebase = Timebase::new(startup.clock())?;
        let mut port = startup
            .bind(&mut source_registry, &mut jobs, &mut contexts, timebase)
            .map_err(|r| r.reason)?;
        let source = port.source();
        let mut draw = Draw(10);
        let mut slots = Crypto::new();
        let mut previous: Option<pure::Request<'_>> = None;
        let mut retired_scope: Option<tunnel::Scope<'_>> = None;
        let mut queued_copy: Option<pure::Request<'_>> = None;
        for ordinal in 1..=3_u8 {
            let peer = *EddsaPrivateKey::from_seed([ordinal; 32])
                .public_key()
                .as_bytes();
            let context = registry.allocate(local, peer)?;
            let scope = context.scope();
            assert_eq!(registry.available(), 0);
            if let Some(old) = retired_scope {
                assert_ne!(scope, old);
                assert!(!old.is_live());
                assert!(scope.allocation() > old.allocation());
            }
            let now = port.timebase().sample()?.monotonic;
            let mut bi = connection::Instance::new();
            let mut ns = [NeighborSlot::new(); 2];
            let mut rs = [RouteSlot::<4>::new(); 2];
            let mut os = [OriginSlot::new(); 1];
            let mut buf = [[0; 512]; 2];
            let mut fs = buf.each_mut().map(|b| FrameSlot::new(b));
            let mut book = Book::new(
                &mut bi,
                local,
                &mut ns,
                &mut rs,
                &mut os,
                &mut fs,
                now,
                connection::Limits::default(),
            )?;
            let neighbor = setup(&mut book, local, peer, now)?;
            let mut controller = Controller::new_external_identity(
                context,
                source,
                book.reset_authority(),
                slots.stores(),
                tunnel::controller::Limits::default(),
                now,
            )?;
            let remote = EcdheSecret::from_bytes([60 + ordinal; 32]);
            let request = mint(
                &mut controller,
                &mut book,
                neighbor,
                &remote,
                now,
                &mut draw,
            )?;
            assert_eq!(request.generation().value(), 1);
            if let Some(old) = previous {
                // A live deadline cannot explain the one-row ledger reuse.
                assert!(now < old.expires());
                assert!(!request.generation().same_context(old.generation()));
                assert_eq!(port.submit(old), Err(Error::StaleGeneration));
            }
            if ordinal == 1 {
                // No submit occurred, so no native high-water can protect this
                // copied capability. Dropping its lease alone must revoke it.
                drop(controller);
                assert_eq!(request.admission(), Err(Error::StaleGeneration));
                assert_eq!(port.submit(request), Err(Error::StaleGeneration));
                assert_eq!(port.report().submitted, 0);
                queued_copy = Some(request);
            } else {
                port.submit(request)?;
                loop {
                    match port.drive(Some(deadline)).await? {
                        Step::Result {
                            request: actual, ..
                        } if actual == request => break,
                        Step::Result { .. } => {
                            return Err("old result selected a replacement allocation".into());
                        }
                        Step::Native(Progress::WaitDeadline) => {
                            return Err("dynamic allocation DH timeout".into());
                        }
                        Step::Lost { .. } | Step::Closed(_) => {
                            return Err("shared source stopped during dynamic reuse".into());
                        }
                        Step::Rejected { reason, .. } => return Err(reason.into()),
                        Step::IdentityChanged { .. } | Step::Retired { .. } => {
                            return Err("original allocation lost its actual DH job".into());
                        }
                        _ => {}
                    }
                }
                let expected = remote.exchange_edwards_hashed(&local)?.into_secret_bytes();
                assert!(matches!(
                    port.finish(request, |bytes| if bytes == &*expected {
                        Ok(())
                    } else {
                        Err(Error::Authentication)
                    })?,
                    pure::Completion::Finished(Ok(()))
                ));
                // This model calls the provider directly; clear the pure queued
                // capability only after actual result/physical ownership settled.
                controller.retire_identity_dh(controller.scope(), &mut port)?;
                controller.close(controller.scope())?;
                drop(controller);
                assert_eq!(port.report().consumed, u64::from(ordinal - 1));
            }
            assert!(!scope.is_live());
            assert_eq!(registry.available(), 1);
            assert_eq!(port.source(), source);
            let queued = queued_copy.ok_or(Error::NotReady)?;
            assert_eq!(port.submit(queued), Err(Error::StaleGeneration));
            previous = Some(request);
            retired_scope = Some(scope);
        }
        assert_eq!(port.report().submitted, 2);
        assert_eq!(port.report().received, 2);
        assert_eq!(port.report().consumed, 2);
        assert_eq!(port.report().stopped, 0);
        let retired = port.close();
        assert!(retired.iter().all(Option::is_none));
        assert_eq!(server.await??, 2);
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
