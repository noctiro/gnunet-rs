//! Real retained Unix MQ recovery after a known queue's numeric refusal.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Original wire/owner assertions use fallible native setup"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_transport::{
    Engine, Limits, PeerId, Signer,
    p2p::{Challenge, Validation},
};
use gnunet_transport_host::{AddressStore, Server, Step};
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
    fn sign_validation(&mut self, bytes: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, bytes)?.as_bytes())
    }
}
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0 += 1;
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = self.0.to_be_bytes()[i % 8];
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
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut b = vec![0; size];
    b[..2].copy_from_slice(&(size as u16).to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    b
}
fn kind(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[2], b[3]])
}
fn queue(peer: PeerId, delta: u64, update: bool) -> Vec<u8> {
    let mut b = frame(
        if update { 1222 } else { 1204 },
        if update { 64 } else { 74 },
    );
    b[4..8].copy_from_slice(&7u32.to_be_bytes());
    b[8..40].copy_from_slice(&peer.0);
    b[44..48].copy_from_slice(&256u32.to_be_bytes());
    b[48..56].copy_from_slice(&delta.to_be_bytes());
    if !update {
        b[64..].copy_from_slice(b"tcp-local\0");
    }
    b
}
async fn read(stream: &mut UnixStream) -> Result<Vec<u8>, std::io::Error> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if n < 4 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&h);
    stream.read_exact(&mut b[4..]).await?;
    Ok(b)
}
async fn sent(stream: &mut UnixStream, b: &[u8]) -> Result<(), std::io::Error> {
    let mut a = frame(1210, 52);
    a[4..8].copy_from_slice(&1u32.to_be_bytes());
    a[8..16].copy_from_slice(&b[8..16]);
    a[16..20].copy_from_slice(&b[4..8]);
    a[20..].copy_from_slice(&b[16..48]);
    stream.write_all(&a).await
}
async fn next_send(stream: &mut UnixStream) -> Result<Vec<u8>, std::io::Error> {
    loop {
        let b = read(stream).await?;
        if kind(&b) == 1209 {
            sent(stream, &b).await?;
            return Ok(b);
        }
    }
}
fn incoming(peer: PeerId, body: &[u8]) -> Vec<u8> {
    let mut b = frame(1202, 88 + body.len());
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[8..16].copy_from_slice(&1u64.to_ne_bytes());
    b[16..24].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    b[24..56].copy_from_slice(&peer.0);
    b[88..].copy_from_slice(body);
    b
}
fn send(peer: PeerId, size: usize) -> Vec<u8> {
    let body = frame(0, size);
    let mut b = frame(363, 40 + size);
    b[8..40].copy_from_slice(&peer.0);
    b[40..].copy_from_slice(&body);
    b
}
#[tokio::test(flavor = "current_thread")]
async fn numeric_refusal_keeps_original_mq_other_peer_and_later_valid_update_live()
-> Result<(), Box<dyn std::error::Error>> {
    let mut key = Key(EddsaPrivateKey::from_seed([3; 32]));
    let a = Key(EddsaPrivateKey::from_seed([5; 32]));
    let b = Key(EddsaPrivateKey::from_seed([7; 32]));
    let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 2, 262140)?;
    let (cs, mut comm) = UnixStream::pair()?;
    let comm_id = server.admit(Connection::from_unix(cs))?;
    let (ss, mut core) = UnixStream::pair()?;
    server.admit(Connection::from_unix(ss))?;
    let refused = Rc::new(Cell::new(0));
    let observed = refused.clone();
    let expected_owner = comm_id.clone();
    let work = async {
        let mut register = frame(1211, 16);
        register[4..8].copy_from_slice(&1u32.to_be_bytes());
        register[12..].copy_from_slice(b"tcp\0");
        comm.write_all(&register).await?;
        let mut start = frame(360, 40);
        start[4..8].copy_from_slice(&2u32.to_be_bytes());
        core.write_all(&start).await?;
        comm.write_all(&queue(a.identity(), 32, false)).await?;
        let challenge = next_send(&mut comm).await?;
        assert_eq!(&challenge[16..48], &a.identity().0);
        assert_eq!(kind(&challenge[48..]), 1303);
        comm.write_all(&queue(a.identity(), u64::MAX - 32, true))
            .await?;
        let mut bad = queue(a.identity(), 2, true);
        bad[44..48].copy_from_slice(&33u32.to_be_bytes());
        bad[56..60].copy_from_slice(&777u32.to_be_bytes());
        comm.write_all(&bad).await?;
        while observed.get() == 0 {
            tokio::task::yield_now().await;
        }
        let c = Challenge::decode(&challenge[48..])?;
        let validity = 1_000_000_000;
        let reply = Validation {
            nonce: c.nonce,
            origin: c.origin,
            validity,
            signature: *a
                .0
                .sign(35, &Validation::signed_region(&c.nonce, validity))?
                .as_bytes(),
        };
        comm.write_all(&incoming(a.identity(), &reply.encode()))
            .await?;
        comm.write_all(&queue(b.identity(), 32, false)).await?;
        loop {
            let out = next_send(&mut comm).await?;
            if out[16..48] == b.identity().0 && kind(&out[48..]) == 1303 {
                let c = Challenge::decode(&out[48..])?;
                let reply = Validation {
                    nonce: c.nonce,
                    origin: c.origin,
                    validity,
                    signature: *b
                        .0
                        .sign(35, &Validation::signed_region(&c.nonce, validity))?
                        .as_bytes(),
                };
                comm.write_all(&incoming(b.identity(), &reply.encode()))
                    .await?;
                break;
            }
        }
        let mut connected = 0;
        while connected < 2 {
            if kind(&read(&mut core).await?) == 361 {
                connected += 1;
            }
        }
        // The refused MTU change did not commit; same physical MQ still emits
        // this raw128-byte frame, then accepts another original queue update.
        core.write_all(&send(a.identity(), 128)).await?;
        loop {
            let out = next_send(&mut comm).await?;
            if kind(&out[48..]) == 0 {
                assert_eq!(&out[16..48], &a.identity().0);
                assert_eq!(out.len(), 48 + 128);
                break;
            }
        }
        comm.write_all(&queue(a.identity(), 1, true)).await?;
        core.write_all(&send(a.identity(), 8)).await?;
        core.write_all(&send(b.identity(), 8)).await?;
        let mut peers = Vec::new();
        while peers.len() < 2 {
            let out = next_send(&mut comm).await?;
            if kind(&out[48..]) == 0 {
                assert_eq!(out.len(), 56);
                peers.push(out[16..48].to_vec());
            }
        }
        assert!(
            peers.contains(&a.identity().0.to_vec()) && peers.contains(&b.identity().0.to_vec())
        );
        assert_eq!(observed.get(), 1);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let mut entropy = Random(0);
    let mut store = Store;
    let drive = async {
        loop {
            match poll_fn(|cx| server.poll_step(cx, None, 100, &mut key, &mut entropy, &mut store))
                .await
            {
                Ok(Step::Progress) => {}
                Ok(Step::InputRejected(r)) => {
                    assert_eq!(r.client, expected_owner);
                    assert_eq!(r.peer, a.identity());
                    assert_eq!(r.queue, 7);
                    assert_eq!(r.reason, Error::Overflow);
                    refused.set(refused.get() + 1);
                }
                Ok(Step::AddressRejected(original)) => break Err(original.reason),
                Ok(Step::WorkDeferred(reason)) => break Err(reason.reason),
                // This case owns only communicator and CORE connections.
                Ok(Step::MonitorRetired(_)) => break Err(Error::Conflict),
                Err(error) => break Err::<(), Error>(error),
            }
        }
    };
    tokio::select! {r=work=>r?,r=drive=>{r?;return Err("driver unexpectedly ended".into());},()=tokio::time::sleep(Duration::from_secs(5))=>return Err("same-MQ recovery timeout".into())}
    assert_eq!(server.engine().snapshot().clients, 2);
    assert_eq!(server.engine().snapshot().connected, 2);
    server.shutdown()?;
    assert_eq!(server.engine().snapshot().clients, 0);
    assert_eq!(server.engine().snapshot().queues, 0);
    Ok(())
}
