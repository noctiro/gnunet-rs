//! Actual owned Unix carrier/MQ boundary fixtures, not normal TCP/C peer proof.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Cancellation and native EOF tests assert exact resource observations"
)]
#[expect(
    dead_code,
    reason = "Shared controlled component adapter has separate Driver and Communicator facades; each existing fixture uses one"
)]
#[path = "support/history.rs"]
mod history;
use core::{
    cell::{Cell, RefCell},
    num::NonZeroUsize,
};
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_session_crypto::{elligator, exchange::EcdheSecret};
use gnunet_tcp_communicator_core::{
    initial,
    session::{
        Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, PROTO_US, Phase, Policy, Scope,
        Session, Time,
    },
    wire,
};
use gnunet_tcp_communicator_host::{Capacity, Clock, PilsFeed};
use gnunet_types::Error;
use history::Driver;
use std::{
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 23) as u8;
        }
        Ok(())
    }
}
fn policy() -> Result<Policy, Error> {
    let mut p = Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
    p.max_backpressure = 1;
    Ok(p)
}
fn time(now: u64) -> Time {
    Time { now, signed: now }
}
fn cap() -> Capacity {
    Capacity {
        ipc_bytes: 65535,
        ipc_frames: 1,
        callbacks: 1,
    }
}
#[tokio::test(flavor = "current_thread")]
async fn cancel_pils_wait_retains_two_header_bytes_and_original_stream()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, mut peer) = UnixStream::pair()?;
    let mut data = vec![0; 176];
    data[..2].copy_from_slice(&176u16.to_be_bytes());
    data[2..4].copy_from_slice(&1831u16.to_be_bytes());
    data[68..72].copy_from_slice(&104u32.to_be_bytes());
    peer.write_all(&data[..2]).await?;
    client.readable().await?;
    let mut feed = PilsFeed::new(Connection::from_unix(client))?;
    {
        let mut waiting = Box::pin(feed.wait());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut waiting).poll(&mut cx).is_pending());
    }
    assert_eq!(feed.update(), None);
    peer.write_all(&data[2..]).await?;
    tokio::time::timeout(Duration::from_secs(1), feed.wait()).await??;
    assert_eq!(feed.update(), Some(data.as_slice()));
    feed.release();
    assert_eq!(feed.update(), None);
    Ok(())
}
struct State {
    now: Cell<u64>,
    revision: Cell<u64>,
    changed: Cell<bool>,
    registered: Cell<bool>,
    backwards_observed: Cell<bool>,
    signed: Cell<u64>,
    waker: RefCell<Option<Waker>>,
}
struct TestClock(Rc<State>);
impl Clock for TestClock {
    fn read(&mut self) -> Result<Time, Error> {
        let n = self.0.now.get();
        if n == 1 {
            self.0.backwards_observed.set(true);
        }
        self.0.signed.set(self.0.signed.get() + 1);
        Ok(Time {
            now: n,
            signed: self.0.signed.get(),
        })
    }
    fn revision(&self) -> u64 {
        self.0.revision.get()
    }
    fn poll_change(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.0.changed.replace(false) {
            Poll::Ready(())
        } else {
            *self.0.waker.borrow_mut() = Some(cx.waker().clone());
            self.0.registered.set(true);
            Poll::Pending
        }
    }
}
fn change(state: &State, n: u64) {
    state.now.set(n);
    state.revision.set(state.revision.get() + 1);
    state.changed.set(true);
    if let Some(w) = state.waker.borrow_mut().take() {
        w.wake();
    }
}
#[tokio::test(flavor = "current_thread")]
async fn logical_revision_rebases_native_wait_and_closes_original_carrier_at_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let key = EddsaPrivateKey::from_seed([2; 32]);
    let ex = EcdheSecret::from_eddsa_seed([2; 32]);
    let mut scope = Scope::new();
    let (mut rx, mut tx, mut pl) = (
        vec![0; wire::MAX_RECORD],
        vec![0; CIPHERTEXT_CAPACITY],
        vec![0; wire::MAX_RECORD],
    );
    let mut callbacks = [CompletionSlot::default()];
    let mut r = Random(33);
    let core = Session::new(
        &mut scope,
        Identity::new(&key, &ex)?,
        None,
        Buffers {
            receive: &mut rx,
            transmit: &mut tx,
            plaintext: &mut pl,
            completions: &mut callbacks,
        },
        policy()?,
        time(100),
        &mut r,
    )?;
    let (carrier, mut remote) = UnixStream::pair()?;
    let (ps, _ps_server) = UnixStream::pair()?;
    let (tr, _tr_server) = UnixStream::pair()?;
    let mut d = Driver::new(
        core,
        Connection::from_unix(carrier),
        [Connection::from_unix(ps), Connection::from_unix(tr)],
        cap(),
        b"tcp-127.0.0.1:80",
        1,
    )?;
    let state = Rc::new(State {
        now: Cell::new(100),
        revision: Cell::new(0),
        changed: Cell::new(false),
        registered: Cell::new(false),
        backwards_observed: Cell::new(false),
        signed: Cell::new(1000),
        waker: RefCell::new(None),
    });
    let mut clock = TestClock(state.clone());
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::try_join!(
            async {
                while d.core().phase() != Phase::Closed {
                    let _activity = d.drive(&mut clock, &mut r).await?;
                }
                Ok::<_, gnunet_tcp_communicator_host::HostError>(())
            },
            async {
                while !state.registered.get() {
                    tokio::task::yield_now().await;
                }
                change(&state, 1);
                while !state.backwards_observed.get() {
                    tokio::task::yield_now().await;
                }
                change(&state, 100 + PROTO_US);
                Ok::<_, gnunet_tcp_communicator_host::HostError>(())
            }
        )
    })
    .await??;
    assert!(state.backwards_observed.get());
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), remote.read(&mut byte)).await??,
        0
    );
    assert!(d.is_quiescent());
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn cancel_virtual_query_before_reconnect_does_not_send_a_ghost_start()
-> Result<(), Box<dyn std::error::Error>> {
    let alice = EddsaPrivateKey::from_seed([1; 32]);
    let bob = EddsaPrivateKey::from_seed([2; 32]);
    let ex = EcdheSecret::from_eddsa_seed([2; 32]);
    let mut scope = Scope::new();
    let (mut rx, mut tx, mut pl) = (
        vec![0; wire::MAX_RECORD],
        vec![0; CIPHERTEXT_CAPACITY],
        vec![0; wire::MAX_RECORD],
    );
    let mut callbacks = [CompletionSlot::default()];
    let mut r = Random(34);
    let p = policy()?;
    let core = Session::new(
        &mut scope,
        Identity::new(&bob, &ex)?,
        None,
        Buffers {
            receive: &mut rx,
            transmit: &mut tx,
            plaintext: &mut pl,
            completions: &mut callbacks,
        },
        p,
        time(0),
        &mut r,
    )?;
    let (carrier, mut remote) = UnixStream::pair()?;
    let (ps, mut ps_server) = UnixStream::pair()?;
    let (tr, _tr_server) = UnixStream::pair()?;
    let mut d = Driver::new(
        core,
        Connection::from_unix(carrier),
        [Connection::from_unix(ps), Connection::from_unix(tr)],
        cap(),
        b"tcp-127.0.0.1:80",
        1,
    )?;
    d.peerstore_lost(time(0))?;
    let mut byte = [0];
    assert_eq!(ps_server.read(&mut byte).await?, 0);
    let special = elligator::Secret::generate(&mut r, p.entropy_attempts)?;
    let (initial, _direction) =
        initial::prepare(&alice, bob.public_key(), &special, 3, 1, &[4; 32])?;
    remote.write_all(&initial).await?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while d.core().phase() != Phase::AwaitingAck {
            let _activity = d.step(time(1), &mut r).await?;
        }
        Ok::<_, gnunet_tcp_communicator_host::HostError>(())
    })
    .await??;
    remote.shutdown().await?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while d.core().phase() != Phase::Closed {
            let _activity = d.step(time(2), &mut r).await?;
        }
        Ok::<_, gnunet_tcp_communicator_host::HostError>(())
    })
    .await??;
    assert!(d.is_quiescent());
    let (replacement, server) = UnixStream::pair()?;
    d.attach_peerstore(Connection::from_unix(replacement))
        .map_err(|r| r.reason)?;
    assert!(
        tokio::time::timeout(Duration::from_millis(2), d.step(time(3), &mut r))
            .await
            .is_err()
    );
    assert!(matches!(server.try_read(&mut byte),Err(e)if e.kind()==std::io::ErrorKind::WouldBlock));
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn continuously_ready_peerstore_cannot_starve_original_native_deadline_close()
-> Result<(), Box<dyn std::error::Error>> {
    let key = EddsaPrivateKey::from_seed([2; 32]);
    let ex = EcdheSecret::from_eddsa_seed([2; 32]);
    let mut scope = Scope::new();
    let (mut rx, mut tx, mut pl) = (
        vec![0; wire::MAX_RECORD],
        vec![0; CIPHERTEXT_CAPACITY],
        vec![0; wire::MAX_RECORD],
    );
    let mut callbacks = [CompletionSlot::default()];
    let mut random = Random(35);
    let core = Session::new(
        &mut scope,
        Identity::new(&key, &ex)?,
        None,
        Buffers {
            receive: &mut rx,
            transmit: &mut tx,
            plaintext: &mut pl,
            completions: &mut callbacks,
        },
        policy()?,
        time(0),
        &mut random,
    )?;
    let (carrier, mut remote) = UnixStream::pair()?;
    let (ps, mut ps_server) = UnixStream::pair()?;
    let (tr, _tr_server) = UnixStream::pair()?;
    let mut driver = Driver::new(
        core,
        Connection::from_unix(carrier),
        [Connection::from_unix(ps), Connection::from_unix(tr)],
        cap(),
        b"tcp-127.0.0.1:80",
        1,
    )?;
    // Unregistered MQ extensions are ignored. Keep far more complete frames
    // readable than the finite dispatch bound; no artificial sleep throttles IO.
    let mut backlog = Vec::new();
    for _ in 0..512 {
        backlog.extend_from_slice(&[0, 4, 0xfd, 0xe8]);
    }
    ps_server.write_all(&backlog).await?;
    let mut turns = 0;
    tokio::time::timeout(Duration::from_secs(1), async {
        while driver.core().phase() != Phase::Closed {
            let _activity = driver.step(time(PROTO_US), &mut random).await?;
            turns += 1;
            assert!(
                turns <= 12,
                "ready local IPC must not starve original cleanup"
            );
        }
        Ok::<_, gnunet_tcp_communicator_host::HostError>(())
    })
    .await??;
    let mut byte = [0];
    assert_eq!(remote.read(&mut byte).await?, 0);
    Ok(())
}
