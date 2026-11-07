//! Real Unix maintenance while an original address STORE is pending.
//! Observer decisions exercise reactor gates, not an Actor retirement or C interop.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native regressions assert original wire, owner and callback facts"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_transport::{
    Engine, Limits, PeerId, Signer, Times, dv,
    dv_bridge::{PacketOutcome, TransferId, TransferOutcome},
    p2p::{Challenge, Validation},
};
use gnunet_transport_host::{
    AddressStore, Server, Step,
    dv_bridge::{NativeAdmission, NativeObserver, Ports},
};
use gnunet_types::Error;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::Instant,
};

type Failure = Box<dyn std::error::Error>;
const TIMES: Times = Times::shared_coordinate(100);
const BLOCKED_FLOW_ID: u64 = 0x3141_5926_5358_9793;
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
        self.0 = self.0.checked_add(1).ok_or(Error::Overflow)?;
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = self.0.to_be_bytes()[index % 8];
        }
        Ok(())
    }
}
#[derive(Debug, Eq, PartialEq)]
struct Address {
    peer: PeerId,
    bytes: Vec<u8>,
    until: u64,
}
#[derive(Default)]
struct GateStore {
    blocked: Option<PeerId>,
    original: Option<Address>,
    completed: Vec<Address>,
    polls: usize,
    waker: Option<Waker>,
}
impl GateStore {
    fn release(&mut self) {
        self.blocked = None;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}
impl AddressStore for GateStore {
    fn validated(&mut self, _: PeerId, _: &[u8], _: u64) -> Result<(), Error> {
        Err(Error::Conflict) // This fixture requires the actual asynchronous port.
    }
    fn poll_validated(
        &mut self,
        cx: &mut Context<'_>,
        peer: PeerId,
        address: &[u8],
        until: u64,
    ) -> Poll<Result<(), Error>> {
        self.polls += 1;
        let observed = Address {
            peer,
            bytes: address.to_vec(),
            until,
        };
        if self.blocked == Some(peer) {
            if let Some(original) = &self.original {
                assert_eq!(
                    &observed, original,
                    "STORE retry changed its original effect"
                );
            } else {
                self.original = Some(observed);
            }
            self.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if let Some(original) = &self.original {
            assert_eq!(
                &observed, original,
                "STORE completion changed its original effect"
            );
        }
        self.completed.push(observed);
        Poll::Ready(Ok(()))
    }
}
struct Observer {
    admission: NativeAdmission,
    ready: usize,
    queued: usize,
    exposed: usize,
}
impl Default for Observer {
    fn default() -> Self {
        Self {
            admission: NativeAdmission::Admit,
            ready: 0,
            queued: 0,
            exposed: 0,
        }
    }
}
impl NativeObserver for Observer {
    fn ready(&mut self, _: &TransferId, _: &Engine) -> Result<NativeAdmission, Error> {
        self.ready += 1;
        Ok(self.admission)
    }
    fn queued(&mut self, _: &TransferId) -> Result<(), Error> {
        self.queued += 1;
        Ok(())
    }
    fn exposed(&mut self, _: &TransferId, bytes: usize) -> Result<(), Error> {
        if bytes == 0 {
            return Err(Error::InvalidInput);
        }
        self.exposed += bytes;
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..2].copy_from_slice(&(size as u16).to_be_bytes());
    bytes[2..4].copy_from_slice(&kind.to_be_bytes());
    bytes
}
fn kind(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[2], bytes[3]])
}
fn queue_frame(peer: PeerId, id: u32) -> Vec<u8> {
    let mut bytes = frame(1204, 74);
    bytes[4..8].copy_from_slice(&id.to_be_bytes());
    bytes[8..40].copy_from_slice(&peer.0);
    bytes[44..48].copy_from_slice(&256u32.to_be_bytes());
    bytes[48..56].copy_from_slice(&32u64.to_be_bytes());
    bytes[64..].copy_from_slice(b"tcp-local\0");
    bytes
}
async fn read(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if size < 4 {
        return Err("short native frame".into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn sent(stream: &mut UnixStream, original: &[u8]) -> Result<(), Failure> {
    let mut bytes = frame(1210, 52);
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[8..16].copy_from_slice(&original[8..16]);
    bytes[16..20].copy_from_slice(&original[4..8]);
    bytes[20..].copy_from_slice(&original[16..48]);
    stream.write_all(&bytes).await?;
    Ok(())
}
fn reply(remote: &Key, output: &[u8]) -> Result<Vec<u8>, Failure> {
    let challenge = Challenge::decode(&output[48..])?;
    let validity = 1_000_000_000;
    let response = Validation {
        nonce: challenge.nonce,
        origin: challenge.origin,
        validity,
        signature: *remote
            .0
            .sign(35, &Validation::signed_region(&challenge.nonce, validity))?
            .as_bytes(),
    };
    let body = response.encode();
    let mut incoming = frame(1202, 88 + body.len());
    incoming[16..24].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    incoming[24..56].copy_from_slice(&remote.identity().0);
    incoming[88..].copy_from_slice(&body);
    Ok(incoming)
}
fn learn(key: &Key, stamp: u64) -> Result<[u8; dv::LEARN_PREFIX], Failure> {
    let challenge = [0x71; 32];
    let signature = key
        .0
        .sign(dv::INIT_PURPOSE, &dv::init_region(stamp, &challenge))?;
    Ok(dv::initiate(
        key.identity(),
        stamp,
        &challenge,
        signature.as_bytes(),
    ))
}
struct Native {
    server: Server,
    key: Key,
    random: Random,
    store: GateStore,
    observer: Observer,
}
impl Native {
    fn new() -> Result<(Self, UnixStream), Failure> {
        let key = Key(EddsaPrivateKey::from_seed([0x63; 32]));
        let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 1, 262140)?;
        let (socket, comm) = UnixStream::pair()?;
        server.admit(Connection::from_unix(socket))?;
        Ok((
            Self {
                server,
                key,
                random: Random(0),
                store: GateStore::default(),
                observer: Observer::default(),
            },
            comm,
        ))
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step, Error>> {
        self.server.poll_step_observed_at(
            cx,
            None,
            TIMES,
            Ports {
                signer: &mut self.key,
                entropy: &mut self.random,
                store: &mut self.store,
            },
            &mut self.observer,
        )
    }
    async fn during<T>(
        &mut self,
        work: impl Future<Output = Result<T, Failure>>,
    ) -> Result<T, Failure> {
        async fn drive(native: &mut Native) -> Result<(), Failure> {
            loop {
                let step = poll_fn(|cx| native.poll(cx)).await?;
                assert_eq!(step, Step::Progress);
            }
        }
        let driving = drive(self);
        tokio::select! {
            result = work => result,
            result = driving => { result?; Err("native driver ended".into()) },
            () = tokio::time::sleep(Duration::from_secs(2)) => Err("native fixture timed out".into()),
        }
    }
    async fn until(&mut self, ready: impl Fn(&Self) -> bool) -> Result<(), Failure> {
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                if ready(self) {
                    return Poll::Ready(Ok(()));
                }
                match self.poll(cx) {
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(step)) => {
                        assert_eq!(step, Step::Progress);
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending => {}
                }
                if ready(self) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }),
        )
        .await??;
        Ok(())
    }
    async fn retry(&mut self) -> Result<(), Failure> {
        poll_fn(|cx| {
            self.server.poll_retry_observed_at(
                cx,
                TIMES,
                &mut self.random,
                &mut self.store,
                &mut self.observer,
            )
        })
        .await?;
        Ok(())
    }
    async fn validate(
        &mut self,
        comm: &mut UnixStream,
        remote: &Key,
        id: u32,
        block: bool,
    ) -> Result<(), Failure> {
        if block {
            self.store.blocked = Some(remote.identity());
        }
        comm.write_all(&queue_frame(remote.identity(), id)).await?;
        self.during(async {
            loop {
                let output = read(comm).await?;
                if kind(&output) != 1209 {
                    continue;
                }
                sent(comm, &output).await?;
                if output[16..48] == remote.identity().0 && kind(&output[48..]) == 1303 {
                    let mut incoming = reply(remote, &output)?;
                    if block {
                        // The same real validation produces its durable STORE
                        // before this original incoming-flow acknowledgement.
                        incoming[4..8].copy_from_slice(&1u32.to_be_bytes());
                        incoming[8..16].copy_from_slice(&BLOCKED_FLOW_ID.to_ne_bytes());
                    }
                    comm.write_all(&incoming).await?;
                    return Ok(());
                }
            }
        })
        .await?;
        if block {
            self.until(|native| native.store.original.is_some()).await?;
        } else {
            self.until(|native| {
                native
                    .store
                    .completed
                    .iter()
                    .any(|address| address.peer == remote.identity())
            })
            .await?;
        }
        Ok(())
    }
}

async fn register(comm: &mut UnixStream) -> Result<(), Failure> {
    let mut bytes = frame(1211, 16);
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[12..].copy_from_slice(b"tcp\0");
    comm.write_all(&bytes).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn pending_store_preserves_fifo_but_allows_admitted_write_and_original_ack()
-> Result<(), Failure> {
    let (mut native, mut comm) = Native::new()?;
    let a = Key(EddsaPrivateKey::from_seed([0x67; 32]));
    let b = Key(EddsaPrivateKey::from_seed([0x71; 32]));
    let c = Key(EddsaPrivateKey::from_seed([0x73; 32]));
    register(&mut comm).await?;
    native.validate(&mut comm, &a, 7, false).await?;
    let source = native.server.dv_attach_source(native.key.identity())?;
    native.validate(&mut comm, &b, 11, true).await?;
    let original = native.store.original.as_ref().ok_or("no original STORE")?;
    assert_eq!(original.peer, b.identity());
    let original_until = original.until;
    assert_eq!(native.store.completed.len(), 1);
    let queue = native
        .server
        .dv_direct_queues(TIMES)
        .find(|queue| queue.peer() == a.identity())
        .ok_or("no original validated queue")?;
    let body = learn(&native.key, 67)?;
    // This explicit trusted native port actually admits1209. It grants neither
    // Actor authenticity nor permission to move later Engine effects past STORE.
    let send = native.server.dv_queue_packet(
        &queue,
        &body,
        true,
        Instant::now() + Duration::from_secs(2),
        TIMES,
    )?;
    assert!(!native.server.dv_send_state(&send)?.ipc_exposed);
    comm.write_all(&queue_frame(c.identity(), 13)).await?;
    native
        .during(async {
            let output = read(&mut comm).await?;
            assert_eq!(
                kind(&output),
                1209,
                "original flow ACK passed pending STORE"
            );
            assert_eq!(&output[16..48], &a.identity().0);
            assert_eq!(&output[48..], &body);
            sent(&mut comm, &output).await?;
            Ok(())
        })
        .await?;
    native
        .until(|native| {
            native
                .server
                .dv_send_state(&send)
                .is_ok_and(|state| state.packet == Some(PacketOutcome::Written))
                && native.server.engine().snapshot().queues == 3
        })
        .await?;
    let actual = native.server.dv_send_state(&send)?;
    assert!(actual.ipc_exposed && actual.ipc_written);
    native.server.dv_take_send(send).map_err(|r| r.reason)?;
    assert_eq!(native.store.completed.len(), 1);
    assert_eq!(
        native.store.original.as_ref().map(|address| address.until),
        Some(original_until)
    );
    assert!(native.store.polls > 1);
    // The blocked validation itself produced this exact flow acknowledgement
    // behind STORE. Maintenance QueueSetup does not pump the third-peer Job.
    assert!(native.server.engine().snapshot().outputs > 0);
    native
        .during(async {
            match tokio::time::timeout(Duration::from_millis(20), read(&mut comm)).await {
                Err(_) => Ok(()),
                Ok(result) => Err(format!("output passed pending STORE: {:?}", result?).into()),
            }
        })
        .await?;
    assert!(native.server.take_native_retirement().is_none());
    native.store.release();
    let acknowledged = native.during(read(&mut comm)).await?;
    assert_eq!(kind(&acknowledged), 1203);
    assert_eq!(&acknowledged[8..16], &BLOCKED_FLOW_ID.to_ne_bytes());
    assert_eq!(&acknowledged[16..48], &b.identity().0);
    // Only after the original STORE and its queued ACK are released may this
    // explicit policy retry pump the retained third-peer challenge Job.
    native.retry().await?;
    native
        .during(async {
            loop {
                let output = read(&mut comm).await?;
                if kind(&output) != 1209 {
                    continue;
                }
                sent(&mut comm, &output).await?;
                if output[16..48] == c.identity().0 {
                    assert_eq!(kind(&output[48..]), 1303);
                    return Ok(());
                }
            }
        })
        .await?;
    assert_eq!(native.store.completed.len(), 2);
    assert_eq!(native.store.completed[1].peer, b.identity());
    assert_eq!(native.store.completed[1].until, original_until);
    native.server.dv_begin_retire_source(&source)?;
    native.server.dv_retire_source(&source)?;
    native.server.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn retiring_observer_yields_before_writing_an_already_admitted_parent() -> Result<(), Failure>
{
    let (mut native, mut comm) = Native::new()?;
    let remote = Key(EddsaPrivateKey::from_seed([0x79; 32]));
    register(&mut comm).await?;
    native.validate(&mut comm, &remote, 7, false).await?;
    let source = native.server.dv_attach_source(native.key.identity())?;
    let queue = native
        .server
        .dv_direct_queues(TIMES)
        .next()
        .ok_or("no validated queue")?;
    let first = learn(&native.key, 71)?;
    let a = native.server.dv_enqueue_output(
        &source,
        &queue,
        &first,
        true,
        Instant::now() + Duration::from_secs(2),
        TIMES,
    )?;
    native.retry().await?; // Actual Framed admission, with no physical write turn.
    let queued = native.server.dv_transfer_state(&a)?;
    assert!(queued.queued && !queued.exposed);
    let second = learn(&native.key, 73)?;
    let b = native.server.dv_enqueue_output(
        &source,
        &queue,
        &second,
        true,
        Instant::now() + Duration::from_secs(2),
        TIMES,
    )?;
    native.observer.admission = NativeAdmission::Deferred;
    let held = poll_fn(|cx| {
        Poll::Ready(native.server.poll_retry_observed_at(
            cx,
            TIMES,
            &mut native.random,
            &mut native.store,
            &mut native.observer,
        ))
    })
    .await;
    assert!(held.is_pending());
    native.observer.admission = NativeAdmission::Retiring;
    let before = native.observer.ready;
    let yielded = poll_fn(|cx| Poll::Ready(native.poll(cx))).await;
    if let Poll::Ready(result) = yielded {
        result?;
    }
    assert!(native.observer.ready > before);
    assert_eq!(native.observer.queued, 1);
    assert_eq!(native.observer.exposed, 0);
    assert!(!native.server.dv_transfer_state(&a)?.exposed);
    assert!(!native.server.dv_transfer_state(&b)?.queued);
    let quiet = tokio::time::timeout(Duration::from_millis(20), read(&mut comm)).await;
    assert!(
        quiet.is_err(),
        "retiring decision allowed native bytes or EOF"
    );
    // Changing this fixture decision does not claim real Actor retirement; it
    // only proves the earlier reactor turn yielded before touching native IO.
    native.observer.admission = NativeAdmission::Admit;
    native.retry().await?;
    native
        .during(async {
            for expected in [&first[..], &second[..]] {
                loop {
                    let output = read(&mut comm).await?;
                    if kind(&output) == 1209 {
                        assert_eq!(&output[48..], expected);
                        sent(&mut comm, &output).await?;
                        break;
                    }
                }
            }
            Ok(())
        })
        .await?;
    native
        .until(|native| {
            [&a, &b].into_iter().all(|id| {
                native
                    .server
                    .dv_transfer_state(id)
                    .is_ok_and(|state| state.outcome == Some(TransferOutcome::Written))
            })
        })
        .await?;
    native.server.dv_take_transfer(a).map_err(|r| r.reason)?;
    native.server.dv_take_transfer(b).map_err(|r| r.reason)?;
    assert!(native.server.take_native_retirement().is_none());
    native.server.dv_begin_retire_source(&source)?;
    native.server.dv_retire_source(&source)?;
    native.server.shutdown()?;
    Ok(())
}
