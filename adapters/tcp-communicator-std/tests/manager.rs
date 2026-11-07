//! Actual shared IPC/native ownership and routing boundaries, not C peer evidence.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite actual-resource fixtures assert original routing and cleanup outcomes"
)]
#[expect(
    dead_code,
    reason = "Shared controlled component adapter has separate Driver and Communicator facades; each existing fixture uses one"
)]
#[path = "support/history.rs"]
mod history;
use core::num::NonZeroUsize;
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_session_crypto::exchange::EcdheSecret;
use gnunet_tcp_communicator_core::{
    session::{
        Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, Phase, Policy, Scope, Session, Time,
    },
    wire,
};
use gnunet_tcp_communicator_host::{Capacity, Connect, HostError, ManagerCapacity};
use gnunet_types::Error;
use history::Communicator;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixStream},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> std::result::Result<(), Error> {
        for b in out {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 23) as u8;
        }
        Ok(())
    }
}
struct Storage {
    scope: Scope,
    rx: Vec<u8>,
    tx: Vec<u8>,
    plain: Vec<u8>,
    callbacks: [CompletionSlot; 1],
}
impl Storage {
    fn new() -> Self {
        Self {
            scope: Scope::new(),
            rx: vec![0; wire::MAX_RECORD],
            tx: vec![0; CIPHERTEXT_CAPACITY],
            plain: vec![0; wire::MAX_RECORD],
            callbacks: [CompletionSlot::default()],
        }
    }
    fn core<'a>(
        &'a mut self,
        key: &'a EddsaPrivateKey,
        exchange: &'a EcdheSecret,
        outbound: bool,
        rng: &mut Random,
    ) -> std::result::Result<Box<Session<'a>>, Error> {
        let mut policy = Policy::reference(NonZeroUsize::new(256).ok_or(Error::InvalidInput)?);
        policy.max_backpressure = 1;
        Ok(Box::new(Session::new(
            &mut self.scope,
            Identity::new(key, exchange)?,
            outbound.then(|| EddsaPrivateKey::from_seed([9; 32]).public_key()),
            Buffers {
                receive: &mut self.rx,
                transmit: &mut self.tx,
                plaintext: &mut self.plain,
                completions: &mut self.callbacks,
            },
            policy,
            time(),
            rng,
        )?))
    }
}
fn time() -> Time {
    Time { now: 1, signed: 1 }
}
fn services() -> io::Result<([Connection; 2], UnixStream, UnixStream)> {
    let (ps, ps_server) = UnixStream::pair()?;
    let (tr, tr_server) = UnixStream::pair()?;
    Ok((
        [Connection::from_unix(ps), Connection::from_unix(tr)],
        ps_server,
        tr_server,
    ))
}
fn manager(
    services: [Connection; 2],
    sessions: usize,
) -> std::result::Result<Communicator<'static>, HostError> {
    Communicator::new(
        services,
        Capacity {
            ipc_bytes: 65535,
            ipc_frames: 8,
            callbacks: 1,
        },
        ManagerCapacity {
            sessions,
            pending_sends: 1,
            commands: 2,
        },
    )
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let n = u16::from_be_bytes([h[0], h[1]]) as usize;
    if n < 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&h);
    stream.read_exact(&mut b[4..]).await?;
    Ok(b)
}
fn create(peer: &EddsaPrivateKey) -> Vec<u8> {
    let mut b = vec![0; 45];
    b[..2].copy_from_slice(&45u16.to_be_bytes());
    b[2..4].copy_from_slice(&1206u16.to_be_bytes());
    b[4..8].copy_from_slice(&[1, 2, 3, 4]);
    b[8..40].copy_from_slice(peer.public_key().as_bytes());
    b[40..].copy_from_slice(b"tcp\0\0");
    b.pop();
    b[..2].copy_from_slice(&44u16.to_be_bytes());
    b
}
async fn command(m: &mut Communicator<'_>, rng: &mut Random) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(1), async {
        while m.command().is_none() {
            let _activity = m.step(time(), rng).await?;
        }
        Ok::<_, HostError>(())
    })
    .await??;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn fragmented_create_is_owned_once_and_epoch_and_process_tokens_cannot_ack_new_requests()
-> Result<()> {
    let key = EddsaPrivateKey::from_seed([7; 32]);
    let mut rng = Random(4);
    let (s, _ps, mut tr) = services()?;
    let mut a = manager(s, 2)?;
    let bytes = create(&key);
    tr.write_all(&bytes[..2]).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(3), command(&mut a, &mut rng))
            .await
            .is_err()
    );
    assert!(a.command().is_none());
    tr.write_all(&bytes[2..]).await?;
    command(&mut a, &mut rng).await?;
    let request = a.command().ok_or(Error::NotReady)?;
    let old = request.id;
    assert_eq!(request.wire_id, [1, 2, 3, 4]);
    assert_eq!(request.address, b"tcp");
    let (s, _ps2, mut tr2) = services()?;
    let mut b = manager(s, 2)?;
    tr2.write_all(&bytes).await?;
    command(&mut b, &mut rng).await?;
    assert!(matches!(
        b.created(&old, true),
        Err(HostError::Core(Error::Stale))
    ));
    assert!(b.command().is_some());
    drop(tr);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if a.step(time(), &mut rng)
                .await
                .is_err_and(|error| error.transport_io_retired())
            {
                break;
            }
        }
    })
    .await?;
    let (new_tr, mut new_server) = UnixStream::pair()?;
    a.attach_transport(Connection::from_unix(new_tr))
        .map_err(|r| r.reason)?;
    new_server.write_all(&bytes).await?;
    command(&mut a, &mut rng).await?;
    assert!(matches!(
        a.created(&old, true),
        Err(HostError::Core(Error::Stale))
    ));
    let next = a.command().ok_or(Error::NotReady)?.id;
    a.created(&next, false)?;
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::try_join!(
            async {
                while !a.is_quiescent() {
                    let _activity = a.step(time(), &mut rng).await?;
                }
                Ok::<_, HostError>(())
            },
            async {
                let first = frame(&mut new_server)
                    .await
                    .map_err(|error| HostError::Transport(error.into()))?;
                assert_eq!(&first[2..4], &1211u16.to_be_bytes());
                let fail = frame(&mut new_server)
                    .await
                    .map_err(|error| HostError::Transport(error.into()))?;
                assert_eq!(&fail[2..4], &1208u16.to_be_bytes());
                assert_eq!(&fail[4..], [1, 2, 3, 4]);
                Ok::<_, HostError>(())
            }
        )?;
        Ok::<_, HostError>(())
    })
    .await??;
    assert!(matches!(
        a.created(&next, true),
        Err(HostError::Core(Error::Stale))
    ));
    new_server.write_all(&bytes).await?;
    command(&mut a, &mut rng).await?;
    let closing = a.command().ok_or(Error::NotReady)?.id;
    a.begin_shutdown(time())?;
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::try_join!(
            async {
                while !a.is_quiescent() {
                    let _activity = a.step(time(), &mut rng).await?;
                }
                Ok::<_, HostError>(())
            },
            async {
                let fail = frame(&mut new_server)
                    .await
                    .map_err(|error| HostError::Transport(error.into()))?;
                assert_eq!(&fail[2..4], &1208u16.to_be_bytes());
                assert_eq!(&fail[4..], [1, 2, 3, 4]);
                Ok::<_, HostError>(())
            }
        )?;
        Ok::<_, HostError>(())
    })
    .await??;
    assert!(matches!(
        a.created(&closing, true),
        Err(HostError::Core(Error::Stale))
    ));
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn two_retained_real_connects_survive_canceled_wait_then_retire_without_id_reuse()
-> Result<()> {
    let key = EddsaPrivateKey::from_seed([2; 32]);
    let exchange = EcdheSecret::from_eddsa_seed([2; 32]);
    let mut storage = [
        Storage::new(),
        Storage::new(),
        Storage::new(),
        Storage::new(),
    ];
    let mut slots = storage.iter_mut();
    let (s, ps, mut tr) = services()?;
    let mut m = Communicator::new(
        s,
        Capacity {
            ipc_bytes: 65535,
            ipc_frames: 8,
            callbacks: 1,
        },
        ManagerCapacity {
            sessions: 2,
            pending_sends: 1,
            commands: 2,
        },
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let mut rng = Random(99);
    let mut ids = Vec::new();
    for index in 0..2 {
        let core = slots
            .next()
            .ok_or(Error::Capacity)?
            .core(&key, &exchange, true, &mut rng)?;
        let connect: Connect<'_> = Box::pin(async move {
            let stream = TcpStream::connect(address).await?;
            stream.set_nodelay(true)?;
            if index == 0 {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Ok(Connection::from_tcp(stream))
        });
        ids.push(
            m.admit_connecting(core, connect, b"tcp-127.0.0.1:1", 1)
                .map_err(|r| r.reason)?,
        );
    }
    {
        let mut waiting = Box::pin(m.step(time(), &mut rng));
        let mut cx = Context::from_waker(Waker::noop());
        let _first = Pin::new(&mut waiting).poll(&mut cx);
    }
    let received = Arc::new(AtomicUsize::new(0));
    let driver_received = received.clone();
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            async {
                while ids
                    .iter()
                    .any(|id| m.core(id).is_ok_and(|c| c.phase() != Phase::Closed))
                {
                    if driver_received.load(Ordering::SeqCst) == 1 {
                        m.lost(&ids[0])?;
                    }
                    let _activity = m.step(time(), &mut rng).await?;
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            async {
                let (mut a, _) = listener.accept().await?;
                let (mut b, _) = listener.accept().await?;
                let mut initial = [0; 168];
                b.read_exact(&mut initial).await?;
                b.shutdown().await?;
                received.store(1, Ordering::SeqCst);
                let mut byte = [0];
                assert_eq!(a.read(&mut byte).await?, 0);
                received.store(2, Ordering::SeqCst);
                Ok::<_, Box<dyn std::error::Error>>(())
            }
        )?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    let registration = frame(&mut tr).await?;
    assert_eq!(&registration[2..4], &1211u16.to_be_bytes());
    let mut byte = [0];
    assert!(matches!(tr.try_read(&mut byte),Err(e)if e.kind()==io::ErrorKind::WouldBlock));
    assert!(matches!(ps.try_read(&mut byte),Err(e)if e.kind()==io::ErrorKind::WouldBlock));
    let old = ids[0].clone();
    drop(m.retire(&old)?);
    assert!(matches!(m.core(&old), Err(Error::Stale)));
    let core = slots
        .next()
        .ok_or(Error::Capacity)?
        .core(&key, &exchange, false, &mut rng)?;
    let (carrier, _remote) = UnixStream::pair()?;
    let next = m
        .admit(core, Connection::from_unix(carrier), b"tcp-127.0.0.1:2", 1)
        .map_err(|r| r.reason)?;
    assert_ne!(old, next);
    assert!(matches!(m.lost(&old), Err(Error::Stale)));
    m.lost(&next)?;
    while m.core(&next)?.phase() != Phase::Closed {
        let _activity = m.step(time(), &mut rng).await?;
    }
    let (s, _ps2, _tr2) = services()?;
    let mut other = Communicator::new(
        s,
        Capacity {
            ipc_bytes: 65535,
            ipc_frames: 8,
            callbacks: 1,
        },
        ManagerCapacity {
            sessions: 1,
            pending_sends: 1,
            commands: 1,
        },
    )?;
    let core = slots
        .next()
        .ok_or(Error::Capacity)?
        .core(&key, &exchange, false, &mut rng)?;
    let (carrier, _remote) = UnixStream::pair()?;
    let foreign = other
        .admit(core, Connection::from_unix(carrier), b"tcp-127.0.0.1:3", 1)
        .map_err(|r| r.reason)?;
    assert!(matches!(m.core(&foreign), Err(Error::Stale)));
    assert!(matches!(other.core(&old), Err(Error::Stale)));
    Ok(())
}
fn ps_record(rid: u32, peer: &EddsaPrivateKey, value: u64) -> Vec<u8> {
    let subsystem = gnunet_tcp_communicator_core::services::SUBSYSTEM;
    let key = gnunet_tcp_communicator_core::session::ReplayKind::Handshake.key();
    let ss = subsystem.len() + 1;
    let ks = key.len() + 1;
    let size = 60 + ss + ks + 8;
    let mut b = vec![0; size];
    b[..2].copy_from_slice(&(size as u16).to_be_bytes());
    b[2..4].copy_from_slice(&822u16.to_be_bytes());
    b[4..36].copy_from_slice(peer.public_key().as_bytes());
    b[44..48].copy_from_slice(&rid.to_be_bytes());
    b[52..54].copy_from_slice(&(ks as u16).to_be_bytes());
    b[54..56].copy_from_slice(&8u16.to_be_bytes());
    b[56..58].copy_from_slice(&(ss as u16).to_be_bytes());
    b[60..60 + ss - 1].copy_from_slice(subsystem);
    b[60 + ss..60 + ss + ks - 1].copy_from_slice(key);
    b[60 + ss + ks..].copy_from_slice(&value.to_be_bytes());
    b
}
fn result(kind: u16, rid: u32, status: i32) -> [u8; 12] {
    let mut b = [0; 12];
    b[..2].copy_from_slice(&12u16.to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    b[4..8].copy_from_slice(&rid.to_be_bytes());
    b[8..].copy_from_slice(&status.to_be_bytes());
    b
}
fn number(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        b.get(at..at + 4).ok_or(Error::Truncated)?.try_into()?,
    ))
}
#[tokio::test(flavor = "current_thread")]
async fn same_peer_scan_store_barrier_survives_closed_owner_and_never_regresses_next_session()
-> Result<()> {
    use gnunet_session_crypto::elligator;
    use gnunet_tcp_communicator_core::initial;
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ex = EcdheSecret::from_eddsa_seed([2; 32]);
    let mut rng = Random(104);
    let mut storage = [Storage::new(), Storage::new()];
    let mut slots = storage.iter_mut();
    let (s, mut ps, _tr) = services()?;
    let mut m = Communicator::new(
        s,
        Capacity {
            ipc_bytes: 65535,
            ipc_frames: 8,
            callbacks: 1,
        },
        ManagerCapacity {
            sessions: 2,
            pending_sends: 1,
            commands: 2,
        },
    )?;
    let mut remotes = Vec::new();
    let mut ids = Vec::new();
    for stamp in [1000, 2000] {
        let core = slots
            .next()
            .ok_or(Error::Capacity)?
            .core(&bob, &ex, false, &mut rng)?;
        let (native, mut remote) = UnixStream::pair()?;
        let special = elligator::Secret::generate(
            &mut rng,
            NonZeroUsize::new(256).ok_or(Error::InvalidInput)?,
        )?;
        let (bytes, _direction) =
            initial::prepare(&alice, bob.public_key(), &special, 1, stamp, &[4; 32])?;
        remote.write_all(&bytes).await?;
        ids.push(
            m.admit(core, Connection::from_unix(native), b"tcp-127.0.0.1:12", 1)
                .map_err(|r| r.reason)?,
        );
        remotes.push(remote);
    }
    let closed = Arc::new(AtomicUsize::new(0));
    let observed = closed.clone();
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            async {
                loop {
                    let count = ids
                        .iter()
                        .filter(|id| m.core(id).is_ok_and(|c| c.phase() == Phase::Closed))
                        .count();
                    closed.store(count, Ordering::SeqCst);
                    if count == 2 && m.is_quiescent() {
                        break;
                    }
                    let _activity = m.step(time(), &mut rng).await?;
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            async {
                let query = frame(&mut ps).await?;
                assert_eq!(&query[2..4], &821u16.to_be_bytes());
                let first = number(&query, 36)?;
                tokio::time::sleep(Duration::from_millis(3)).await;
                let mut byte = [0];
                assert!(
                    matches!(ps.try_read(&mut byte),Err(e)if e.kind()==io::ErrorKind::WouldBlock)
                );
                ps.write_all(&ps_record(first, &alice, 0)).await?;
                let next = frame(&mut ps).await?;
                assert_eq!(&next[2..4], &828u16.to_be_bytes());
                assert_eq!(number(&next, 12)?, first);
                // A live iterator receives only NEXT, never a self-feeding replacement.
                ps.write_all(&result(823, first, 0)).await?;
                let store = frame(&mut ps).await?;
                assert_eq!(&store[2..4], &820u16.to_be_bytes());
                let first_store = number(&store, 44)?;
                assert_eq!(&store[store.len() - 8..], &1000u64.to_be_bytes());
                remotes[0].shutdown().await?;
                while observed.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
                tokio::time::sleep(Duration::from_millis(3)).await;
                assert!(
                    matches!(ps.try_read(&mut byte),Err(e)if e.kind()==io::ErrorKind::WouldBlock)
                );
                // Canceling the old core's continuation cannot release the submitted
                // database-write barrier until this actual original service result.
                ps.write_all(&result(827, first_store, 1)).await?;
                let query = frame(&mut ps).await?;
                assert_eq!(&query[2..4], &821u16.to_be_bytes());
                let second = number(&query, 36)?;
                assert_ne!(first, second);
                assert_ne!(first_store, second);
                ps.write_all(&ps_record(second, &alice, 1000)).await?;
                let next = frame(&mut ps).await?;
                assert_eq!(&next[2..4], &828u16.to_be_bytes());
                assert_eq!(number(&next, 12)?, second);
                ps.write_all(&result(823, second, 0)).await?;
                let store = frame(&mut ps).await?;
                assert_eq!(&store[2..4], &820u16.to_be_bytes());
                let second_store = number(&store, 44)?;
                assert_eq!(&store[store.len() - 8..], &2000u64.to_be_bytes());
                ps.write_all(&result(827, second_store, 1)).await?;
                remotes[1].shutdown().await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            }
        )?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    assert!(m.is_quiescent());
    Ok(())
}

/// Actual Unix MQs plus an explicit delayed-backend commit model. This is a
/// Rust ownership/recovery regression, not normal-C interoperability evidence.
#[tokio::test(flavor = "current_thread")]
async fn late_remote_commit_cannot_lower_local_replay_floor_after_mq_replacement() -> Result<()> {
    use gnunet_session_crypto::elligator;
    use gnunet_tcp_communicator_core::initial;
    use std::sync::{Mutex, atomic::AtomicU64};
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ex = EcdheSecret::from_eddsa_seed([2; 32]);
    let mut rng = Random(804);
    let mut storage = [Storage::new(), Storage::new(), Storage::new()];
    let mut slots = storage.iter_mut();
    let (s, mut old_ps, _tr) = services()?;
    let (new_connection, mut new_ps) = UnixStream::pair()?;
    let mut new_connection = Some(Connection::from_unix(new_connection));
    let mut m = Communicator::new(
        s,
        Capacity {
            ipc_bytes: 65535,
            ipc_frames: 8,
            callbacks: 1,
        },
        ManagerCapacity {
            sessions: 2,
            pending_sends: 1,
            commands: 2,
        },
    )?;
    let mut remotes = Vec::new();
    let mut ids = Vec::new();
    for stamp in [1000, 2000] {
        let core = slots
            .next()
            .ok_or(Error::Capacity)?
            .core(&bob, &ex, false, &mut rng)?;
        let (native, mut remote) = UnixStream::pair()?;
        let special = elligator::Secret::generate(
            &mut rng,
            NonZeroUsize::new(256).ok_or(Error::InvalidInput)?,
        )?;
        let (bytes, _) = initial::prepare(&alice, bob.public_key(), &special, 1, stamp, &[4; 32])?;
        remote.write_all(&bytes).await?;
        ids.push(
            m.admit(core, Connection::from_unix(native), b"tcp-127.0.0.1:12", 1)
                .map_err(|r| r.reason)?,
        );
        remotes.push(remote);
    }
    let stage = Arc::new(AtomicUsize::new(0));
    let signal = Arc::new(Mutex::new(None::<Waker>));
    let database = Arc::new(AtomicU64::new(0));
    let admitted_new_write = Arc::new(AtomicUsize::new(0));
    let observed_stage = stage.clone();
    let observed_signal = signal.clone();
    let observed_database = database.clone();
    let observed_admitted = admitted_new_write.clone();
    let mut closing = false;
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::try_join!(
            async {
                loop {
                    let done = std::future::poll_fn(|cx| {
                        if let Ok(mut w) = signal.lock() {
                            *w = Some(cx.waker().clone());
                        }
                        if stage.load(Ordering::SeqCst) == 1 {
                            if let Err(e) = m.peerstore_lost(time()) {
                                return std::task::Poll::Ready(Err(e.into()));
                            }
                            let Some(connection) = new_connection.take() else {
                                return std::task::Poll::Ready(Err(Error::Stale.into()));
                            };
                            if let Err(rejected) = m.attach_peerstore(connection) {
                                return std::task::Poll::Ready(Err(rejected.reason.into()));
                            }
                            stage.store(2, Ordering::SeqCst);
                        }
                        if stage.load(Ordering::SeqCst) == 3 && !closing {
                            for id in &ids {
                                if let Err(e) = m.lost(id) {
                                    return std::task::Poll::Ready(Err(e.into()));
                                }
                            }
                            closing = true;
                        }
                        if closing && m.is_quiescent() {
                            return std::task::Poll::Ready(Ok(true));
                        }
                        match m.poll_step(cx, time(), &mut rng) {
                            std::task::Poll::Ready(Ok(_)) => std::task::Poll::Ready(Ok(false)),
                            std::task::Poll::Ready(Err(HostError::Peerstore(error)))
                                if stage.load(Ordering::SeqCst) == 3 && error.io_retired() =>
                            {
                                std::task::Poll::Ready(Ok(false))
                            }
                            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                            std::task::Poll::Pending => std::task::Poll::Pending,
                        }
                    })
                    .await?;
                    if done {
                        break;
                    }
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            async {
                let query = frame(&mut old_ps).await?;
                assert_eq!(&query[2..4], &821u16.to_be_bytes());
                let rid = number(&query, 36)?;
                old_ps.write_all(&ps_record(rid, &alice, 0)).await?;
                assert_eq!(&frame(&mut old_ps).await?[2..4], &828u16.to_be_bytes());
                old_ps.write_all(&result(823, rid, 0)).await?;
                let old_store = frame(&mut old_ps).await?;
                assert_eq!(&old_store[2..4], &820u16.to_be_bytes());
                assert_eq!(&old_store[old_store.len() - 8..], &1000u64.to_be_bytes());
                // Backend retains this submitted write independently of its now-lost
                // client continuation. No STORE_RESULT has happened or been invented.
                observed_stage.store(1, Ordering::SeqCst);
                if let Some(w) = observed_signal
                    .lock()
                    .map_err(|_| Error::Conflict)?
                    .as_ref()
                {
                    w.wake_by_ref();
                }
                {
                    let query = frame(&mut new_ps).await?;
                    assert_eq!(&query[2..4], &821u16.to_be_bytes());
                    let second = number(&query, 36)?;
                    new_ps
                        .write_all(&ps_record(
                            second,
                            &alice,
                            observed_database.load(Ordering::SeqCst),
                        ))
                        .await?;
                    assert_eq!(&frame(&mut new_ps).await?[2..4], &828u16.to_be_bytes());
                    new_ps.write_all(&result(823, second, 0)).await?;
                    let newer = frame(&mut new_ps).await?;
                    assert_eq!(&newer[2..4], &820u16.to_be_bytes());
                    assert_eq!(&newer[newer.len() - 8..], &2000u64.to_be_bytes());
                    observed_database.store(2000, Ordering::SeqCst);
                    observed_admitted.store(1, Ordering::SeqCst);
                    new_ps
                        .write_all(&result(827, number(&newer, 44)?, 1))
                        .await?;
                }
                // Model the old request finally committing after the newer MQ's
                // scan/commit. REPLACE has no compare-and-set protection on the wire.
                observed_database.store(1000, Ordering::SeqCst);
                for remote in &mut remotes {
                    remote.shutdown().await?;
                }
                observed_stage.store(3, Ordering::SeqCst);
                if let Some(w) = observed_signal
                    .lock()
                    .map_err(|_| Error::Conflict)?
                    .as_ref()
                {
                    w.wake_by_ref();
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            }
        )?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    assert_eq!(admitted_new_write.load(Ordering::SeqCst), 1);
    assert_eq!(database.load(Ordering::SeqCst), 1000);
    assert!(m.is_quiescent());
    for id in &ids {
        drop(m.retire(id)?);
    }

    // A late official REPLACE may lower the remote backend. The same process's
    // retained floor must still reject a signed stamp between the two commits,
    // without admitting another STORE or inventing an iterator result.
    let core = slots
        .next()
        .ok_or(Error::Capacity)?
        .core(&bob, &ex, false, &mut rng)?;
    let (native, mut remote) = UnixStream::pair()?;
    let special =
        elligator::Secret::generate(&mut rng, NonZeroUsize::new(256).ok_or(Error::InvalidInput)?)?;
    let (bytes, _) = initial::prepare(&alice, bob.public_key(), &special, 1, 1500, &[5; 32])?;
    remote.write_all(&bytes).await?;
    let id = m
        .admit(core, Connection::from_unix(native), b"tcp-127.0.0.1:12", 1)
        .map_err(|r| r.reason)?;
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::try_join!(
            async {
                while !m.is_quiescent() {
                    m.step(time(), &mut rng).await?;
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            async {
                let query = frame(&mut new_ps).await?;
                assert_eq!(&query[2..4], &821u16.to_be_bytes());
                let stop = frame(&mut new_ps).await?;
                assert_eq!(&stop[2..4], &829u16.to_be_bytes());
                assert_eq!(&stop[4..8], &query[36..40]);
                Ok::<_, Box<dyn std::error::Error>>(())
            }
        )
    })
    .await??;
    assert_eq!(m.core(&id)?.phase(), Phase::Closed);
    assert!(!m.peerstore_recovery_required());
    Ok(())
}

/// Persistent fixture framing: canceling one bounded manager wait must not lose
/// partially read service headers or consume a different peer's completion.
struct LocalMq {
    stream: UnixStream,
    pending: Vec<u8>,
}
impl LocalMq {
    fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            pending: Vec::new(),
        }
    }
    fn drain(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut bytes = [0; 4096];
        loop {
            match self.stream.try_read(&mut bytes) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Ok(n) => self.pending.extend_from_slice(&bytes[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        let mut frames = Vec::new();
        while self.pending.len() >= 4 {
            let size = u16::from_be_bytes([self.pending[0], self.pending[1]]) as usize;
            if size < 4 {
                return Err(Error::Malformed.into());
            }
            if self.pending.len() < size {
                break;
            }
            frames.push(self.pending.drain(..size).collect());
        }
        Ok(frames)
    }
}
struct ReceiveServices {
    peerstore: LocalMq,
    transport: LocalMq,
    received: Vec<Vec<u8>>,
    queues: usize,
    stores: usize,
}
impl ReceiveServices {
    async fn poll(&mut self) -> Result<()> {
        for query in self.peerstore.drain()? {
            // Replies use the actual submitted operation's ID. The fixture has
            // no old timestamps and acknowledges each admitted store separately.
            let reply = match u16::from_be_bytes([query[2], query[3]]) {
                821 => result(823, number(&query, 36)?, 0),
                820 => {
                    self.stores += 1;
                    result(827, number(&query, 44)?, 1)
                }
                _ => return Err(Error::Malformed.into()),
            };
            self.peerstore.stream.write_all(&reply).await?;
        }
        for message in self.transport.drain()? {
            match u16::from_be_bytes([message[2], message[3]]) {
                1202 => self.received.push(message),
                1204 => {
                    // This fixture reserves one waiting send per physical peer.
                    // Its actual published queue must not claim unlimited room.
                    if message[48..56] != 1u64.to_be_bytes() {
                        return Err("TCP queue exceeded its reserved send capacity".into());
                    }
                    self.queues += 1;
                }
                1205 | 1211 => {}
                _ => return Err(Error::Malformed.into()),
            }
        }
        Ok(())
    }
    async fn complete(&mut self, index: usize) -> Result<()> {
        let message = self.received.get(index).ok_or(Error::NotReady)?;
        let mut ack = [0; 48];
        ack[..2].copy_from_slice(&48u16.to_be_bytes());
        ack[2..4].copy_from_slice(&1203u16.to_be_bytes());
        ack[8..16].copy_from_slice(&message[8..16]);
        ack[16..].copy_from_slice(&message[24..56]);
        self.transport.stream.write_all(&ack).await?;
        Ok(())
    }
}
async fn receive_until(
    manager: &mut Communicator<'_>,
    services: &mut ReceiveServices,
    rng: &mut Random,
    done: impl Fn(&Communicator<'_>, &ReceiveServices) -> bool,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            services.poll().await?;
            if done(manager, services) {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            if let Ok(progress) =
                tokio::time::timeout(Duration::from_millis(1), manager.step(time(), rng)).await
            {
                let _progress = progress?;
            }
        }
    })
    .await?
}
fn payload(size: usize) -> Result<Vec<u8>> {
    let mut message = vec![17; size];
    message[..2].copy_from_slice(&u16::try_from(size)?.to_be_bytes());
    message[2..4].copy_from_slice(&17u16.to_be_bytes());
    Ok(message)
}

/// This executes Rust session crypto over owned Unix carriers and the shared
/// official IPC envelopes. It neither executes a C peer nor changes wire MTUs.
#[tokio::test(flavor = "current_thread")]
async fn oversized_receive_is_local_and_preserves_other_peers_original_callback() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), receive_limit_scenario()).await?
}
async fn receive_limit_scenario() -> Result<()> {
    use gnunet_session_crypto::elligator;
    use gnunet_tcp_communicator_core::initial;

    let peers = [
        EddsaPrivateKey::from_seed([1; 32]),
        EddsaPrivateKey::from_seed([3; 32]),
    ];
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let exchanges = [
        EcdheSecret::from_eddsa_seed([1; 32]),
        EcdheSecret::from_eddsa_seed([3; 32]),
    ];
    let exchange = EcdheSecret::from_eddsa_seed([2; 32]);
    let mut rng = Random(903);
    let mut storage = [Storage::new(), Storage::new()];
    let (connections, ps, tr) = services()?;
    let mut manager = Communicator::new(
        connections,
        Capacity {
            ipc_bytes: 131070,
            ipc_frames: 8,
            callbacks: 1,
        },
        ManagerCapacity {
            sessions: 2,
            pending_sends: 1,
            commands: 2,
        },
    )?;
    let mut services = ReceiveServices {
        peerstore: LocalMq::new(ps),
        transport: LocalMq::new(tr),
        received: Vec::new(),
        queues: 0,
        stores: 0,
    };
    let mut ids = Vec::new();
    let mut remotes = Vec::new();
    let mut directions = Vec::new();
    for (storage, peer) in storage.iter_mut().zip(&peers) {
        let core = storage.core(&bob, &exchange, false, &mut rng)?;
        let (native, mut remote) = UnixStream::pair()?;
        let special = elligator::Secret::generate(
            &mut rng,
            NonZeroUsize::new(256).ok_or(Error::InvalidInput)?,
        )?;
        let (initial, direction) =
            initial::prepare(peer, bob.public_key(), &special, 1, 1000, &[4; 32])?;
        remote.write_all(&initial).await?;
        ids.push(
            manager
                .admit(core, Connection::from_unix(native), b"tcp-127.0.0.1:12", 1)
                .map_err(|rejected| rejected.reason)?,
        );
        remotes.push(remote);
        directions.push(direction);
    }
    receive_until(&mut manager, &mut services, &mut rng, |manager, _| {
        ids.iter().all(|id| {
            manager
                .core(id)
                .is_ok_and(|core| core.phase() == Phase::AwaitingAck && !core.write_interest())
        })
    })
    .await?;
    for (((remote, direction), peer), exchange) in remotes
        .iter_mut()
        .zip(&mut directions)
        .zip(&peers)
        .zip(&exchanges)
    {
        let mut initial = [0; wire::INITIAL_KX];
        tokio::time::timeout(Duration::from_secs(1), remote.read_exact(&mut initial))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "peer initial response"))??;
        let opened = initial::open(
            peer.public_key(),
            exchange,
            Some(bob.public_key()),
            &initial,
        )?;
        let mut ack = wire::acknowledgement(peer, bob.public_key(), 1001, opened.challenge())?;
        direction.handshake_fragment(&mut ack)?;
        remote.write_all(&ack).await?;
    }
    receive_until(
        &mut manager,
        &mut services,
        &mut rng,
        |manager, services| {
            services.queues == 2
                && services.stores == 4
                && ids.iter().all(|id| {
                    manager
                        .core(id)
                        .is_ok_and(|core| core.phase() == Phase::Established)
                })
        },
    )
    .await?;

    assert_eq!(services.stores, 4);
    let mut encrypted = vec![0; wire::MAX_RECORD];
    let healthy = payload(8)?;
    let n = directions[1].seal_box(&healthy, &mut encrypted)?;
    remotes[1].write_all(&encrypted[..n]).await?;
    receive_until(
        &mut manager,
        &mut services,
        &mut rng,
        |manager, services| {
            services.received.len() == 1
                && manager
                    .core(&ids[1])
                    .is_ok_and(|core| core.backpressure() == 1)
        },
    )
    .await?;

    // Both the first unrepresentable envelope and the TCP wire maximum must
    // fail this peer's admission while the other peer owns an uncompleted flow.
    for (failures, size) in [65535 - 88 + 1, 65535].into_iter().enumerate() {
        let n = directions[0].seal_box(&payload(size)?, &mut encrypted)?;
        tokio::try_join!(
            async {
                remotes[0].write_all(&encrypted[..n]).await?;
                Ok::<_, Box<dyn std::error::Error>>(())
            },
            receive_until(&mut manager, &mut services, &mut rng, |manager, _| {
                manager
                    .core(&ids[0])
                    .is_ok_and(|core| core.diagnostics().admission_failures == failures as u64 + 1)
            })
        )?;
        assert_eq!(manager.core(&ids[0])?.backpressure(), 0);
        assert_eq!(manager.core(&ids[1])?.backpressure(), 1);
        assert_eq!(manager.core(&ids[1])?.diagnostics().admission_failures, 0);
        assert_eq!(manager.core(&ids[0])?.phase(), Phase::Established);
        assert_eq!(manager.core(&ids[1])?.phase(), Phase::Established);
        assert_eq!(services.received.len(), 1);
        assert_eq!(services.stores, 4);
        assert!(!manager.peerstore_recovery_required());
    }

    // Exactly 65535-88 bytes still fit the existing official IPC limit. Rejects
    // neither allocate flow IDs nor acknowledge the other peer's retained token.
    let boundary = payload(65535 - 88)?;
    let n = directions[0].seal_box(&boundary, &mut encrypted)?;
    tokio::try_join!(
        async {
            remotes[0].write_all(&encrypted[..n]).await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        },
        receive_until(
            &mut manager,
            &mut services,
            &mut rng,
            |manager, services| {
                services.received.len() == 2
                    && manager
                        .core(&ids[0])
                        .is_ok_and(|core| core.backpressure() == 1)
            }
        )
    )?;
    assert_eq!(services.received[1].len(), 65535);
    assert_eq!(&services.received[1][88..], &boundary);
    assert_eq!(
        &services.received[0][24..56],
        peers[1].public_key().as_bytes()
    );
    assert_eq!(
        &services.received[1][24..56],
        peers[0].public_key().as_bytes()
    );
    assert_eq!(&services.received[0][8..16], &0u64.to_ne_bytes());
    assert_eq!(&services.received[1][8..16], &1u64.to_ne_bytes());
    services.complete(1).await?;
    receive_until(&mut manager, &mut services, &mut rng, |manager, _| {
        manager
            .core(&ids[0])
            .is_ok_and(|core| core.backpressure() == 0)
    })
    .await?;
    assert_eq!(manager.core(&ids[1])?.backpressure(), 1);
    services.complete(0).await?;
    receive_until(&mut manager, &mut services, &mut rng, |manager, _| {
        manager
            .core(&ids[1])
            .is_ok_and(|core| core.backpressure() == 0)
    })
    .await?;
    for id in &ids {
        assert_eq!(manager.core(id)?.phase(), Phase::Established);
        assert_eq!(manager.core(id)?.diagnostics().receive_failures, 0);
        manager.lost(id)?;
    }
    receive_until(&mut manager, &mut services, &mut rng, |manager, _| {
        manager.is_quiescent()
    })
    .await?;
    assert_eq!(manager.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn actual_address_fifo_and_claimed_create_result_survive_capacity_and_shutdown() -> Result<()>
{
    let key = EddsaPrivateKey::from_seed([7; 32]);
    let mut rng = Random(4);
    let (s, _ps, mut tr) = services()?;
    let mut m = manager(s, 1)?;
    tr.write_all(&create(&key)).await?;
    command(&mut m, &mut rng).await?;
    let id = m.command().ok_or(Error::NotReady)?.id;
    m.claim_create(&id)?;
    assert!(matches!(
        m.claim_create(&id),
        Err(HostError::Core(Error::Stale))
    ));
    let mut published = 0u32;
    loop {
        match m.advertise(published + 17, b"tcp-127.0.0.1:1000", 1) {
            Ok(()) => published += 1,
            Err(HostError::Core(Error::WouldBlock)) => break,
            Err(e) => return Err(e.into()),
        }
    }
    assert!(published > 0);
    assert!(matches!(
        m.created(&id, true),
        Err(HostError::Core(Error::WouldBlock))
    ));
    m.begin_shutdown(time())?;
    // The claimed original admission remains pending; the manager must not create
    // an automatic 1208 rejection simply because shutdown began.
    assert!(m.command().is_some());
    let mut completed = false;
    let mut removed = false;
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::try_join!(
            async {
                loop {
                    if !completed {
                        match m.created(&id, true) {
                            Ok(()) => completed = true,
                            Err(HostError::Core(Error::WouldBlock)) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    if completed && !removed {
                        match m.withdraw(17) {
                            Ok(()) => removed = true,
                            Err(HostError::Core(Error::WouldBlock)) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    if completed && removed && m.is_quiescent() {
                        break;
                    }
                    let _original = m.step(time(), &mut rng).await?;
                }
                Ok::<_, HostError>(())
            },
            async {
                let mut registered = false;
                let mut adds = 0u32;
                let mut success = false;
                loop {
                    let b = frame(&mut tr)
                        .await
                        .map_err(|error| HostError::Transport(error.into()))?;
                    match u16::from_be_bytes([b[2], b[3]]) {
                        1211 => {
                            assert!(!registered);
                            registered = true;
                        }
                        1200 => {
                            assert!(registered);
                            assert!(!success);
                            assert_eq!(&b[4..8], &(adds + 17).to_be_bytes());
                            adds += 1;
                        }
                        1207 => {
                            assert!(registered);
                            assert_eq!(adds, published);
                            assert!(!success);
                            assert_eq!(&b[4..], [1, 2, 3, 4]);
                            success = true;
                        }
                        1201 => {
                            assert!(success);
                            assert_eq!(&b[4..8], &17u32.to_be_bytes());
                            break;
                        }
                        kind => {
                            return Err(HostError::Core(if kind == 1208 {
                                Error::Conflict
                            } else {
                                Error::Malformed
                            }));
                        }
                    }
                }
                Ok::<_, HostError>(())
            }
        )?;
        Ok::<_, HostError>(())
    })
    .await??;
    assert!(completed && removed);
    assert!(m.command().is_none());
    assert!(matches!(
        m.created(&id, false),
        Err(HostError::Core(Error::Stale))
    ));
    Ok(())
}
