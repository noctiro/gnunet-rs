//! Real Unix MQ + UDP + durable replay + independent Rust TRANSPORT server.
//! ACKs travel through actual1212/1213/1220 production routing, never a test grant.
#![cfg(feature = "transport")]

use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_transport::{Engine, Limits, PeerId, Signer};
use gnunet_transport_host::{AddressStore, Server};
use gnunet_types::Error;
use gnunet_udp_communicator_core::{Identity, send::Mode};
use gnunet_udp_communicator_host::{
    driver::{Activity, Capacity, Configuration, Driver},
    replay::Journal,
    socket::DatagramSocket,
};
use std::{
    future::poll_fn,
    net::SocketAddr,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::net::UnixStream;
type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "udp-driver-{}-{}",
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
struct Random;
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(out).map_err(|_| Error::Entropy)
    }
}
struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, b: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, b)?.as_bytes())
    }
}
struct Store;
impl AddressStore for Store {
    fn validated(&mut self, _: PeerId, _: &[u8], _: u64) -> Result<(), Error> {
        Ok(())
    }
}
async fn actual_direct_peer(bind: SocketAddr) -> Test {
    let scratch = Scratch::new()?;
    let da = scratch.0.join("a");
    let db = scratch.0.join("b");
    std::fs::create_dir(&da)?;
    std::fs::create_dir(&db)?;
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut ak = Key(EddsaPrivateKey::from_seed([3; 32]));
    let mut bk = Key(EddsaPrivateKey::from_seed([5; 32]));
    let mut sa = Server::new(Engine::new(ak.identity(), Limits::default())?, 1, 262140)?;
    let mut sb = Server::new(Engine::new(bk.identity(), Limits::default())?, 1, 262140)?;
    let (aservice, acommunicator) = UnixStream::pair()?;
    let (bservice, bcommunicator) = UnixStream::pair()?;
    sa.admit(Connection::from_unix(aservice))?;
    sb.admit(Connection::from_unix(bservice))?;
    let asocket = DatagramSocket::bind(bind)?;
    let bsocket = DatagramSocket::bind(bind)?;
    let atarget = bsocket.local_address();
    let btarget = asocket.local_address();
    let mut policy = asocket.profile().sender_policy();
    policy.secrets = 16;
    let capacity = Capacity {
        io_slice: 1,
        ..Capacity::default()
    };
    let mut adriver = Driver::new(
        Connection::from_unix(acommunicator),
        asocket,
        Configuration {
            local: a.peer(),
            peer: b.peer(),
            target: atarget,
            network: 1,
            capacity,
            transmit: policy,
        },
        100,
    )?;
    let mut bdriver = Driver::new(
        Connection::from_unix(bcommunicator),
        bsocket,
        Configuration {
            local: b.peer(),
            peer: a.peer(),
            target: btarget,
            network: 1,
            capacity,
            transmit: policy,
        },
        100,
    )?;
    let mut ah = Journal::open(&da, a.peer(), 8)?;
    let mut bh = Journal::open(&db, b.peer(), 8)?;
    let mut random = Random;
    let mut store = Store;
    let mut boxes = [0; 2];
    let mut initials = [0; 2];
    let mut turns = 0u64;
    poll_fn(|cx| {
        let mut progress = false;
        for _ in 0..8 {
            if let Poll::Ready(result) =
                sa.poll_step(cx, None, 100, &mut ak, &mut random, &mut store)
            {
                result?;
                progress = true;
            }
            if let Poll::Ready(result) =
                sb.poll_step(cx, None, 100, &mut bk, &mut random, &mut store)
            {
                result?;
                progress = true;
            }
            for (index, driver, identity, history) in [
                (0, &mut adriver, &a, &mut ah),
                (1, &mut bdriver, &b, &mut bh),
            ] {
                if let Poll::Ready(result) =
                    driver.poll_step(cx, identity, history, 100, &mut random)
                {
                    match result? {
                        Activity::NativeSent {
                            mode: Mode::Initial,
                            ..
                        } => initials[index] += 1,
                        Activity::NativeSent {
                            mode: Mode::Box { .. },
                            ..
                        } => boxes[index] += 1,
                        _ => {}
                    }
                    progress = true;
                }
            }
            turns += 1;
            if sa.engine().snapshot().connected == 1
                && sb.engine().snapshot().connected == 1
                && boxes.iter().all(|count| *count > 0)
            {
                return Poll::Ready(Ok::<(), Box<dyn std::error::Error>>(()));
            }
            if turns > 200000 {
                return Poll::Ready(Err(Error::Timeout.into()));
            }
        }
        if progress {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await?;
    assert!(initials.iter().all(|n| *n > 0));
    assert!(boxes.iter().all(|n| *n > 0));
    assert!(ah.commits() > 0 && bh.commits() > 0);
    // Explicit shutdown drains original queue teardown then real MQ EOF; it does
    // not substitute a local callback for native or remote delivery.
    adriver.finish()?;
    bdriver.finish()?;
    poll_fn(|cx| {
        let mut progress = false;
        for _ in 0..8 {
            if let Poll::Ready(result) =
                sa.poll_step(cx, None, 100, &mut ak, &mut random, &mut store)
            {
                result?;
                progress = true;
            }
            if let Poll::Ready(result) =
                sb.poll_step(cx, None, 100, &mut bk, &mut random, &mut store)
            {
                result?;
                progress = true;
            }
            for (driver, identity, history) in
                [(&mut adriver, &a, &mut ah), (&mut bdriver, &b, &mut bh)]
            {
                if !driver.is_quiescent()
                    && let Poll::Ready(result) =
                        driver.poll_step(cx, identity, history, 100, &mut random)
                {
                    result?;
                    progress = true;
                }
            }
            if adriver.is_quiescent()
                && bdriver.is_quiescent()
                && sa.engine().snapshot().clients == 0
                && sb.engine().snapshot().clients == 0
            {
                return Poll::Ready(Ok::<(), Box<dyn std::error::Error>>(()));
            }
        }
        if progress {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await?;
    assert!(ah.quiescent()? && bh.quiescent()?);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_unix_ipc_ipv4_udp_backchannel_crypto_credit_and_original_teardown() -> Test {
    tokio::time::timeout(
        Duration::from_secs(10),
        actual_direct_peer("127.0.0.1:0".parse()?),
    )
    .await?
}
#[tokio::test(flavor = "current_thread")]
async fn actual_unix_ipc_ipv6_udp_backchannel_crypto_credit_and_original_teardown() -> Test {
    tokio::time::timeout(
        Duration::from_secs(10),
        actual_direct_peer("[::1]:0".parse()?),
    )
    .await?
}
