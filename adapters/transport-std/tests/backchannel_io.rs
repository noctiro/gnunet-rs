//! Actual official backchannel IPC, retained physical owners and prefix routing.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite actual Unix ownership assertions with fallible setup"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_transport::{
    Engine, Limits, PeerId, Signer, Snapshot,
    p2p::{Challenge, Validation},
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
async fn wait_token(s: &mut UnixStream, token: u64) -> Result<(), std::io::Error> {
    loop {
        let b = read(s).await?;
        if kind(&b) == 1203 && b[8..16] == token.to_ne_bytes() {
            return Ok(());
        }
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

fn udp_register() -> Vec<u8> {
    let mut b = frame(1211, 16);
    b[4..8].copy_from_slice(&2u32.to_be_bytes());
    b[12..].copy_from_slice(b"udp\0");
    b
}
fn notify(peer: PeerId) -> Vec<u8> {
    let mut b = frame(1212, 116);
    b[8..40].copy_from_slice(&peer.0);
    let mut ack = frame(1460, 72);
    ack[4..8].copy_from_slice(&128u32.to_be_bytes());
    ack[8..].fill(0x44);
    b[40..112].copy_from_slice(&ack);
    b[112..].copy_from_slice(b"udp\0");
    b
}
#[tokio::test(flavor = "current_thread")]
async fn actual_backchannel_keeps_carrier_and_target_distinct_and_routes_only_current_prefix_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let mut key = Key(EddsaPrivateKey::from_seed([3; 32]));
    let remote = Key(EddsaPrivateKey::from_seed([5; 32]));
    let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 3, 262140)?;
    let (cs, mut carrier) = UnixStream::pair()?;
    server.admit(Connection::from_unix(cs))?;
    let (us, mut udp) = UnixStream::pair()?;
    server.admit(Connection::from_unix(us))?;
    let (ns, mut replacement) = UnixStream::pair()?;
    server.admit(Connection::from_unix(ns))?;
    let state = Rc::new(Cell::<Snapshot>::new(server.engine().snapshot()));
    let seen = state.clone();
    let phase = Rc::new(Cell::new(0));
    let observed_phase = phase.clone();
    let work = async move {
        phase.set(1);
        let mut register = frame(1211, 16);
        register[4..8].copy_from_slice(&1u32.to_be_bytes());
        register[12..].copy_from_slice(b"tcp\0");
        carrier.write_all(&register).await?;
        udp.write_all(&udp_register()).await?;
        add_remote(&mut carrier, &remote, 7, 1).await?;
        phase.set(2);
        udp.write_all(&notify(remote.identity())).await?;
        let sent = next_send(&mut carrier).await?;
        assert_eq!(kind(&sent[48..]), 1213);
        assert_eq!(sent.len(), 128);
        assert_eq!(&sent[52..124], &notify(remote.identity())[40..112]);
        assert_eq!(&sent[124..], b"udp\0");
        phase.set(3);
        carrier
            .write_all(&incoming(remote.identity(), &sent[48..], 2))
            .await?;
        let received = read(&mut udp).await?;
        assert_eq!(kind(&received), 1220);
        assert_eq!(received.len(), 112);
        assert_eq!(&received[4..8], &[0; 4]);
        assert_eq!(&received[8..40], &remote.identity().0);
        assert_eq!(&received[40..], &notify(remote.identity())[40..112]);
        wait_token(&mut carrier, 2).await?;
        phase.set(4);
        drop(udp);
        while seen.get().clients != 2 {
            tokio::task::yield_now().await;
        }
        phase.set(5);
        replacement.write_all(&udp_register()).await?;
        // Registration has no wire ACK. A request processed on this same replacement
        // MQ provides the barrier before injecting through a different carrier MQ.
        replacement.write_all(&notify(remote.identity())).await?;
        let replacement_sent = next_send(&mut carrier).await?;
        assert_eq!(kind(&replacement_sent[48..]), 1213);
        carrier
            .write_all(&incoming(remote.identity(), &replacement_sent[48..], 3))
            .await?;
        phase.set(6);
        let received = read(&mut replacement).await?;
        assert_eq!(kind(&received), 1220);
        assert_eq!(&received[40..], &notify(remote.identity())[40..112]);
        wait_token(&mut carrier, 3).await?;
        phase.set(7);
        let mut malformed = sent[48..].to_vec();
        *malformed.last_mut().ok_or(Error::Truncated)? = 1;
        carrier
            .write_all(&incoming(remote.identity(), &malformed, 4))
            .await?;
        wait_token(&mut carrier, 4).await?;
        assert_eq!(seen.get().clients, 2);
        assert_eq!(seen.get().connected, 1);
        assert_eq!(seen.get().remote_dropped, 1);
        phase.set(8);
        replacement.write_all(&notify(remote.identity())).await?;
        assert_eq!(kind(&next_send(&mut carrier).await?[48..]), 1213);
        phase.set(9);
        drop(carrier);
        drop(replacement);
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
                Err(e) => break Err::<(), Error>(e),
            }
        }
    };
    tokio::select! {r=work=>r?,r=drive=>{r?;return Err("backchannel driver ended".into());},()=tokio::time::sleep(Duration::from_secs(5))=>return Err(format!("backchannel owner timeout phase={} state={:?}",observed_phase.get(),state.get()).into())}
    server.shutdown()?;
    let after = server.engine().snapshot();
    assert_eq!(after.clients, 0);
    assert_eq!(after.queues, 0);
    assert_eq!(after.attempts, 0);
    assert_eq!(after.pending, 0);
    Ok(())
}
