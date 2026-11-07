//! Real Unix EOF retires the original unreliable owner before a new CORE client.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite native original-owner and wire assertions with fallible setup"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_transport::{
    Engine, Limits, PeerId, Signer, Snapshot,
    p2p::{Challenge, Reliable, Validation, encode_acknowledgements},
};
use gnunet_transport_host::{AddressStore, Server};
use gnunet_types::Error;
use std::{cell::Cell, future::poll_fn, rc::Rc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, b: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, b)?.as_bytes())
    }
}
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        self.0 += 1;
        for (i, v) in b.iter_mut().enumerate() {
            *v = self.0.to_be_bytes()[i % 8];
        }
        Ok(())
    }
}
struct Store;
impl AddressStore for Store {
    fn validated(&mut self, _: PeerId, _: &[u8], _: u64) -> Result<(), Error> {
        Ok(())
    }
}
fn frame(kind: u16, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    b[..2].copy_from_slice(&(n as u16).to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    b
}
fn kind(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[2], b[3]])
}
async fn read(s: &mut UnixStream) -> Result<Vec<u8>, std::io::Error> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if n < 4 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&h);
    s.read_exact(&mut b[4..]).await?;
    Ok(b)
}
async fn next_send(s: &mut UnixStream) -> Result<Vec<u8>, std::io::Error> {
    loop {
        let b = read(s).await?;
        if kind(&b) == 1209 {
            let mut a = frame(1210, 52);
            a[4..8].copy_from_slice(&1u32.to_be_bytes());
            a[8..16].copy_from_slice(&b[8..16]);
            a[16..20].copy_from_slice(&b[4..8]);
            a[20..].copy_from_slice(&b[16..48]);
            s.write_all(&a).await?;
            return Ok(b);
        }
    }
}
fn incoming(peer: PeerId, b: &[u8], token: u64) -> Vec<u8> {
    let mut out = frame(1202, 88 + b.len());
    out[4..8].copy_from_slice(&1u32.to_be_bytes());
    out[8..16].copy_from_slice(&token.to_ne_bytes());
    out[16..24].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    out[24..56].copy_from_slice(&peer.0);
    out[88..].copy_from_slice(b);
    out
}
fn send(peer: PeerId, n: usize) -> Vec<u8> {
    let mut b = frame(363, 40 + n);
    b[8..40].copy_from_slice(&peer.0);
    b[40..].copy_from_slice(&frame(0, n));
    b
}
async fn wait_token(s: &mut UnixStream, token: u64) -> Result<(), std::io::Error> {
    loop {
        let b = read(s).await?;
        if kind(&b) == 1203 && b[8..16] == token.to_ne_bytes() {
            return Ok(());
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn physical_core_eof_erases_its_remote_ack_authority_before_same_mq_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let mut key = Key(EddsaPrivateKey::from_seed([3; 32]));
    let remote = Key(EddsaPrivateKey::from_seed([5; 32]));
    let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 3, 262140)?;
    let (cs, mut comm) = UnixStream::pair()?;
    server.admit(Connection::from_unix(cs))?;
    let (as_, mut a) = UnixStream::pair()?;
    server.admit(Connection::from_unix(as_))?;
    let (bs, mut b) = UnixStream::pair()?;
    server.admit(Connection::from_unix(bs))?;
    let state = Rc::new(Cell::<Snapshot>::new(server.engine().snapshot()));
    let seen = state.clone();
    let work = async move {
        let mut register = frame(1211, 16);
        register[4..8].copy_from_slice(&2u32.to_be_bytes());
        register[12..].copy_from_slice(b"udp\0");
        comm.write_all(&register).await?;
        let mut start = frame(360, 40);
        start[4..8].copy_from_slice(&2u32.to_be_bytes());
        a.write_all(&start).await?;
        let mut queue = frame(1204, 74);
        queue[4..8].copy_from_slice(&7u32.to_be_bytes());
        queue[8..40].copy_from_slice(&remote.identity().0);
        queue[44..48].copy_from_slice(&256u32.to_be_bytes());
        queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
        queue[64..].copy_from_slice(b"udp-local\0");
        comm.write_all(&queue).await?;
        let challenge = next_send(&mut comm).await?;
        let c = Challenge::decode(&challenge[48..])?;
        let validity = 1_000_000_000;
        let reply = Validation {
            nonce: c.nonce,
            origin: c.origin,
            validity,
            signature: *remote
                .0
                .sign(35, &Validation::signed_region(&c.nonce, validity))?
                .as_bytes(),
        };
        comm.write_all(&incoming(remote.identity(), &reply.encode(), 1))
            .await?;
        assert_eq!(kind(&read(&mut a).await?), 361);
        a.write_all(&send(remote.identity(), 16)).await?;
        assert_eq!(kind(&read(&mut a).await?), 364);
        let first = next_send(&mut comm).await?;
        let old = Reliable::decode(&first[48..])?.uuid;
        drop(a);
        while seen.get().clients != 2 || seen.get().pending_remote_acks != 0 {
            tokio::task::yield_now().await;
        }
        b.write_all(&start).await?;
        assert_eq!(kind(&read(&mut b).await?), 361);
        b.write_all(&send(remote.identity(), 32)).await?;
        assert_eq!(kind(&read(&mut b).await?), 364);
        let second = next_send(&mut comm).await?;
        let fresh = Reliable::decode(&second[48..])?.uuid;
        assert_ne!(old, fresh);
        let mut ack = [0; 32];
        encode_acknowledgements(1, &[(0, old)], &mut ack)?;
        comm.write_all(&incoming(remote.identity(), &ack, 22))
            .await?;
        wait_token(&mut comm, 22).await?;
        assert_eq!(seen.get().pending_remote_acks, 1);
        encode_acknowledgements(2, &[(0, fresh)], &mut ack)?;
        comm.write_all(&incoming(remote.identity(), &ack, 23))
            .await?;
        wait_token(&mut comm, 23).await?;
        assert_eq!(seen.get().pending_remote_acks, 0);
        drop(b);
        drop(comm);
        while seen.get().clients != 0 {
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let mut entropy = Random(0);
    let mut store = Store;
    let drive = async {
        loop {
            match poll_fn(|cx| server.poll_step(cx, None, 100, &mut key, &mut entropy, &mut store))
                .await
            {
                Ok(_) => state.set(server.engine().snapshot()),
                Err(error) => break Err::<(), Error>(error),
            }
        }
    };
    tokio::select! {r=work=>r?,r=drive=>{r?;return Err("owner driver unexpectedly ended".into());},()=tokio::time::sleep(Duration::from_secs(5))=>return Err("actual Unix unreliable owner timeout".into())}
    server.shutdown()?;
    let after = server.engine().snapshot();
    assert_eq!(after.clients, 0);
    assert_eq!(after.queues, 0);
    assert_eq!(after.pending, 0);
    assert_eq!(after.pending_remote_acks, 0);
    assert_eq!(after.attempts, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn actual_late_local_callback_after_five_seconds_keeps_same_mq_and_requires_explicit_grant()
-> Result<(), Box<dyn std::error::Error>> {
    use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
    let mut key = Key(EddsaPrivateKey::from_seed([3; 32]));
    let remote = Key(EddsaPrivateKey::from_seed([5; 32]));
    let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 2, 262140)?;
    let (cs, mut comm) = UnixStream::pair()?;
    server.admit(Connection::from_unix(cs))?;
    let (ss, mut core) = UnixStream::pair()?;
    server.admit(Connection::from_unix(ss))?;
    let state = Rc::new(Cell::new(server.engine().snapshot()));
    let seen = state.clone();
    let enabled = Rc::new(Cell::new(false));
    let enable = enabled.clone();
    let work = async move {
        let mut register = frame(1211, 16);
        register[4..8].copy_from_slice(&2u32.to_be_bytes());
        register[12..].copy_from_slice(b"udp\0");
        comm.write_all(&register).await?;
        let mut start = frame(360, 40);
        start[4..8].copy_from_slice(&2u32.to_be_bytes());
        core.write_all(&start).await?;
        let mut queue = frame(1204, 74);
        queue[4..8].copy_from_slice(&7u32.to_be_bytes());
        queue[8..40].copy_from_slice(&remote.identity().0);
        queue[44..48].copy_from_slice(&256u32.to_be_bytes());
        queue[48..56].copy_from_slice(&2u64.to_be_bytes());
        queue[64..].copy_from_slice(b"udp-local\0");
        comm.write_all(&queue).await?;
        let challenge = next_send(&mut comm).await?;
        let c = Challenge::decode(&challenge[48..])?;
        let validity = 1_000_000_000;
        let reply = Validation {
            nonce: c.nonce,
            origin: c.origin,
            validity,
            signature: *remote
                .0
                .sign(35, &Validation::signed_region(&c.nonce, validity))?
                .as_bytes(),
        };
        comm.write_all(&incoming(remote.identity(), &reply.encode(), 1))
            .await?;
        assert_eq!(kind(&read(&mut core).await?), 361);
        core.write_all(&send(remote.identity(), 16)).await?;
        assert_eq!(kind(&read(&mut core).await?), 364);
        let first = loop {
            let b = read(&mut comm).await?;
            if kind(&b) == 1209 {
                break b;
            }
        };
        let uuid = Reliable::decode(&first[48..])?.uuid;
        // Actual elapsed wall time, with native canonical-clock timer sampling;
        // the original data MID deliberately receives no local callback yet.
        enable.set(true);
        tokio::time::sleep(Duration::from_millis(5100)).await;
        assert_eq!(seen.get().expired_attempts, 1);
        assert_eq!(seen.get().attempts, 0);
        assert_eq!(seen.get().pending_remote_acks, 1);
        let mut late = frame(1210, 52);
        late[4..8].copy_from_slice(&1u32.to_be_bytes());
        late[8..16].copy_from_slice(&first[8..16]);
        late[16..20].copy_from_slice(&first[4..8]);
        late[20..].copy_from_slice(&first[16..48]);
        comm.write_all(&late).await?;
        let mut ack = [0; 32];
        encode_acknowledgements(1, &[(0, [0x77; 16])], &mut ack)?;
        comm.write_all(&incoming(remote.identity(), &ack, 222))
            .await?;
        wait_token(&mut comm, 222).await?;
        assert_eq!(seen.get().clients, 2);
        assert_eq!(seen.get().attempts, 0);
        assert_eq!(seen.get().pending_remote_acks, 1);
        let mut update = queue[..64].to_vec();
        update[..4].copy_from_slice(&[0, 64, 4, 198]);
        update[48..56].copy_from_slice(&1u64.to_be_bytes());
        comm.write_all(&update).await?;
        let retry = next_send(&mut comm).await?;
        assert_ne!(retry[8..16], first[8..16]);
        assert_eq!(Reliable::decode(&retry[48..])?.uuid, uuid);
        encode_acknowledgements(2, &[(0, uuid)], &mut ack)?;
        comm.write_all(&incoming(remote.identity(), &ack, 333))
            .await?;
        wait_token(&mut comm, 333).await?;
        assert_eq!(seen.get().pending_remote_acks, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), core.read_u8())
                .await
                .is_err()
        );
        // Evict the bounded callback tombstone through actual original
        // callbacks, then prove an unrelated peer still progresses on this MQ.
        let other = Key(EddsaPrivateKey::from_seed([7; 32]));
        let mut second = queue.clone();
        second[4..8].copy_from_slice(&9u32.to_be_bytes());
        second[8..40].copy_from_slice(&other.identity().0);
        second[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
        comm.write_all(&second).await?;
        let challenge = loop {
            let b = next_send(&mut comm).await?;
            if kind(&b[48..]) == 1303 && b[16..48] == other.identity().0 {
                break b;
            }
        };
        let c = Challenge::decode(&challenge[48..])?;
        let reply = Validation {
            nonce: c.nonce,
            origin: c.origin,
            validity,
            signature: *other
                .0
                .sign(35, &Validation::signed_region(&c.nonce, validity))?
                .as_bytes(),
        };
        comm.write_all(&incoming(other.identity(), &reply.encode(), 2))
            .await?;
        assert_eq!(kind(&read(&mut core).await?), 361);
        let mut best = send(other.identity(), 8);
        best[4..8].copy_from_slice(&16u32.to_be_bytes());
        for _ in 0..260 {
            core.write_all(&best).await?;
            assert_eq!(kind(&read(&mut core).await?), 364);
            loop {
                let packet = next_send(&mut comm).await?;
                if kind(&packet[48..]) == 0 && packet[16..48] == other.identity().0 {
                    break;
                }
            }
        }
        late[4..8].copy_from_slice(&0u32.to_be_bytes());
        comm.write_all(&late).await?;
        encode_acknowledgements(3, &[(0, [0x77; 16])], &mut ack)?;
        comm.write_all(&incoming(other.identity(), &ack, 444))
            .await?;
        wait_token(&mut comm, 444).await?;
        assert!(seen.get().ignored_local_callbacks >= 1);
        assert_eq!(seen.get().clients, 2);
        assert_eq!(seen.get().connected, 2);
        assert_eq!(seen.get().pending_remote_acks, 0);
        core.write_all(&best).await?;
        assert_eq!(kind(&read(&mut core).await?), 364);
        loop {
            let packet = next_send(&mut comm).await?;
            if kind(&packet[48..]) == 0 && packet[16..48] == other.identity().0 {
                break;
            }
        }
        drop(core);
        drop(comm);
        while seen.get().clients != 0 {
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let mut entropy = Random(0);
    let mut store = Store;
    let clock = SystemClock;
    let mut timer = tokio::time::interval(Duration::from_millis(10));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let drive = async {
        loop {
            tokio::select! {
                r=poll_fn(|cx|{let now=match clock.sample(){Ok(s)=>s.now.as_micros(),Err(e)=>return std::task::Poll::Ready(Err(e))};server.poll_step(cx,None,now,&mut key,&mut entropy,&mut store)})=>match r{Ok(_)=>state.set(server.engine().snapshot()),Err(e)=>break Err::<(),Error>(e)},
                _=timer.tick()=>{if enabled.get(){server.tick(clock.sample()?.now.as_micros(),&mut entropy,&mut store)?;state.set(server.engine().snapshot());}},
            }
        }
    };
    tokio::select! {r=work=>r?,r=drive=>{r?;return Err("late-callback driver unexpectedly ended".into());},()=tokio::time::sleep(Duration::from_secs(15))=>return Err("actual late callback timeout".into())}
    server.shutdown()?;
    let after = server.engine().snapshot();
    assert_eq!(after.clients, 0);
    assert_eq!(after.attempts, 0);
    assert_eq!(after.pending_remote_acks, 0);
    assert_eq!(after.pending, 0);
    Ok(())
}

struct FallibleRandom {
    random: Random,
    fail: Rc<Cell<bool>>,
}
impl Entropy for FallibleRandom {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        if self.fail.replace(false) {
            return Err(Error::Entropy);
        }
        self.random.fill(b)
    }
}
async fn add_remote(
    comm: &mut UnixStream,
    remote: &Key,
    qid: u32,
    token: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&qid.to_be_bytes());
    queue[8..40].copy_from_slice(&remote.identity().0);
    queue[44..48].copy_from_slice(&256u32.to_be_bytes());
    queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    queue[64..].copy_from_slice(b"udp-local\0");
    comm.write_all(&queue).await?;
    let challenge = loop {
        let b = next_send(comm).await?;
        if kind(&b[48..]) == 1303 && b[16..48] == remote.identity().0 {
            break b;
        }
    };
    let c = Challenge::decode(&challenge[48..])?;
    let validity = 1_000_000_000;
    let reply = Validation {
        nonce: c.nonce,
        origin: c.origin,
        validity,
        signature: *remote
            .0
            .sign(35, &Validation::signed_region(&c.nonce, validity))?
            .as_bytes(),
    };
    comm.write_all(&incoming(remote.identity(), &reply.encode(), token))
        .await?;
    wait_token(comm, token).await?;
    Ok(())
}
fn flow(window: u64, sequence: u32) -> Vec<u8> {
    gnunet_transport::p2p::Flow {
        sequence,
        inbound_window: window,
        outbound_sent: 0,
        outbound_window: 131072,
        sender_time: u64::from(sequence) + 100,
        rtt: 10_000,
        sync_ready: true,
    }
    .encode()
    .to_vec()
}
// A shared communicator carries protocol control and application data together.
// Acknowledge every original local MID, validate permitted control frames, then
// return the next data frame without relaxing its peer/body/offset assertions.
async fn resource_payload(
    comm: &mut UnixStream,
    peers: [PeerId; 2],
    controls: &mut usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    loop {
        let packet = next_send(comm).await?;
        if kind(&packet[48..]) != 1221 {
            return Ok(packet);
        }
        let peer = &packet[16..48];
        assert!(peers.iter().any(|p| p.0.as_slice() == peer));
        let flow = gnunet_transport::p2p::Flow::decode(&packet[48..])?;
        assert!(flow.sync_ready);
        *controls += 1;
        assert!(
            *controls <= 8,
            "unexpected control flood during bounded fixture"
        );
    }
}
#[tokio::test(flavor = "current_thread")]
async fn accepted_flow_entropy_failure_keeps_shared_mq_and_other_peer_io_live()
-> Result<(), Box<dyn std::error::Error>> {
    let mut key = Key(EddsaPrivateKey::from_seed([3; 32]));
    let a = Key(EddsaPrivateKey::from_seed([5; 32]));
    let b = Key(EddsaPrivateKey::from_seed([7; 32]));
    let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 2, 262140)?;
    let (cs, mut comm) = UnixStream::pair()?;
    server.admit(Connection::from_unix(cs))?;
    let (ss, mut core) = UnixStream::pair()?;
    server.admit(Connection::from_unix(ss))?;
    let state = Rc::new(Cell::new(server.engine().snapshot()));
    let seen = state.clone();
    let fail = Rc::new(Cell::new(false));
    let fail_next = fail.clone();
    let deferrals = Rc::new(Cell::new(0));
    let observed = deferrals.clone();
    let retry = Rc::new(Cell::new(false));
    let request_retry = retry.clone();
    let a_peer = a.identity();
    let work = async move {
        let mut controls = 0;
        let mut register = frame(1211, 16);
        register[4..8].copy_from_slice(&1u32.to_be_bytes());
        register[12..].copy_from_slice(b"tcp\0");
        comm.write_all(&register).await?;
        let mut start = frame(360, 40);
        start[4..8].copy_from_slice(&2u32.to_be_bytes());
        core.write_all(&start).await?;
        add_remote(&mut comm, &a, 3, 1).await?;
        assert_eq!(kind(&read(&mut core).await?), 361);
        add_remote(&mut comm, &b, 9, 2).await?;
        assert_eq!(kind(&read(&mut core).await?), 361);
        comm.write_all(&incoming(a.identity(), &flow(0, 1), 3))
            .await?;
        wait_token(&mut comm, 3).await?;
        core.write_all(&send(a.identity(), 512)).await?;
        while seen.get().pending != 1 {
            tokio::task::yield_now().await;
        }
        fail_next.set(true);
        comm.write_all(&incoming(a.identity(), &flow(131072, 2), 4))
            .await?;
        wait_token(&mut comm, 4).await?;
        assert_eq!(observed.get(), 1);
        // The accepted FLOW must not close the shared physical owner or retry
        // A implicitly when a later, unrelated B input is dispatched.
        let mut body = frame(0, 8);
        body[4..].copy_from_slice(&0x12345678u32.to_be_bytes());
        comm.write_all(&incoming(b.identity(), &body, 5)).await?;
        let received = read(&mut core).await?;
        assert_eq!(kind(&received), 365);
        assert_eq!(&received[36..], &body);
        wait_token(&mut comm, 5).await?;
        core.write_all(&send(b.identity(), 8)).await?;
        let credit = read(&mut core).await?;
        assert_eq!(kind(&credit), 364);
        assert_eq!(&credit[8..40], &b.identity().0);
        let packet =
            resource_payload(&mut comm, [a.identity(), b.identity()], &mut controls).await?;
        assert_eq!(kind(&packet[48..]), 0);
        assert_eq!(&packet[16..48], &b.identity().0);
        assert_eq!(seen.get().clients, 2);
        assert_eq!(seen.get().connected, 2);
        assert_eq!(seen.get().pending, 1);
        assert_eq!(observed.get(), 1);
        request_retry.set(true);
        let credit = read(&mut core).await?;
        assert_eq!(kind(&credit), 364);
        assert_eq!(&credit[8..40], &a.identity().0);
        let mut rebuilt = Vec::new();
        for expected in [0, 224, 448] {
            let packet =
                resource_payload(&mut comm, [a.identity(), b.identity()], &mut controls).await?;
            assert_eq!(&packet[16..48], &a.identity().0);
            let f = gnunet_transport::p2p::Fragment::decode(&packet[48..])?;
            assert_eq!(f.offset, expected);
            rebuilt.extend_from_slice(f.body);
        }
        assert_eq!(rebuilt, frame(0, 512));
        assert_eq!(observed.get(), 1);
        drop(core);
        drop(comm);
        while seen.get().clients != 0 {
            tokio::task::yield_now().await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let mut entropy = FallibleRandom {
        random: Random(0),
        fail,
    };
    let mut store = Store;
    let mut timer = tokio::time::interval(Duration::from_millis(1));
    let drive = async {
        loop {
            tokio::select! {
                r=poll_fn(|cx|server.poll_step(cx,None,100,&mut key,&mut entropy,&mut store))=>match r {
                    Ok(gnunet_transport_host::Step::WorkDeferred(reason))=>{
                        assert_eq!(reason.reason,Error::Entropy);assert_eq!(reason.peer,a_peer);
                        assert_eq!(server.engine().deferred_work().collect::<Vec<_>>(),vec![reason]);
                        deferrals.set(deferrals.get()+1);state.set(server.engine().snapshot());
                    },
                    Ok(_)=>state.set(server.engine().snapshot()),Err(e)=>break Err::<(),Error>(e),
                },
                _=timer.tick()=>{
                    // Normal scheduled ticks do not reattempt the failed original,
                    // even though entropy has become healthy after its one refusal.
                    server.tick(100,&mut entropy,&mut store)?;
                    if retry.replace(false) {server.retry_deferred(100,&mut entropy,&mut store)?;}
                    state.set(server.engine().snapshot());
                },
            }
        }
    };
    tokio::select! {r=work=>r?,r=drive=>{r?;return Err("resource driver unexpectedly ended".into());},()=tokio::time::sleep(Duration::from_secs(5))=>return Err("shared resource IO timeout".into())}
    server.shutdown()?;
    assert_eq!(server.engine().snapshot().pending, 0);
    Ok(())
}
