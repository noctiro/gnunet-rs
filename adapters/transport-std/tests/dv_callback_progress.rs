//! Real Unix communicator framing and queue validation, with no Actor driven.
//! Quarantined DV bytes are not authentication, application delivery or C interop.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native regressions assert original wire, callback and source-generation facts"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_transport::{
    Engine, Limits, PeerId, Signer, Times, dv,
    dv_bridge::{Ingress, Source, TransferId, TransferOutcome},
    p2p::{Challenge, Validation},
};
use gnunet_transport_host::{
    AddressStore, DvRetirementWork, NativeGuardEvent, RetirementCause, Server, Step,
    dv_bridge::{NativeAdmission, NativeObserver, Ports},
};
use gnunet_types::Error;
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::Instant,
};

type Failure = Box<dyn std::error::Error>;
const TIMES: Times = Times::shared_coordinate(100);
const FLOW_ID: u64 = 0x1020_3040_5060_7080;
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
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = self.0.to_be_bytes()[i % 8];
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
#[derive(Default)]
struct Observer {
    parent: Option<TransferId>,
    blocked: bool,
    queued: usize,
    exposed: usize,
}
impl NativeObserver for Observer {
    fn ready(&mut self, parent: &TransferId, _: &Engine) -> Result<NativeAdmission, Error> {
        if self.parent.as_ref() != Some(parent) {
            return Err(Error::Stale);
        }
        Ok(if self.blocked {
            NativeAdmission::Deferred
        } else {
            NativeAdmission::Admit
        })
    }
    fn queued(&mut self, parent: &TransferId) -> Result<(), Error> {
        if self.parent.as_ref() != Some(parent) {
            return Err(Error::Stale);
        }
        self.queued += 1;
        Ok(())
    }
    fn exposed(&mut self, parent: &TransferId, bytes: usize) -> Result<(), Error> {
        if self.parent.as_ref() != Some(parent) || bytes == 0 {
            return Err(Error::Conflict);
        }
        self.exposed = self.exposed.checked_add(bytes).ok_or(Error::Overflow)?;
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
    let mut ack = frame(1210, 52);
    ack[4..8].copy_from_slice(&1u32.to_be_bytes());
    ack[8..16].copy_from_slice(&original[8..16]);
    ack[16..20].copy_from_slice(&original[4..8]);
    ack[20..].copy_from_slice(&original[16..48]);
    stream.write_all(&ack).await?;
    Ok(())
}
fn incoming(peer: PeerId, body: &[u8], flow: bool) -> Vec<u8> {
    let mut bytes = frame(1202, 88 + body.len());
    bytes[4..8].copy_from_slice(&u32::from(flow).to_be_bytes());
    bytes[8..16].copy_from_slice(&FLOW_ID.to_ne_bytes());
    bytes[16..24].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    bytes[24..56].copy_from_slice(&peer.0);
    bytes[88..].copy_from_slice(body);
    bytes
}
fn learn(key: &Key, stamp: u64) -> Result<[u8; dv::LEARN_PREFIX], Failure> {
    let challenge = [0x61; 32];
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
async fn step(
    server: &mut Server,
    key: &mut Key,
    random: &mut Random,
    observer: &mut Observer,
) -> Result<(), Failure> {
    step_at(server, key, random, observer, TIMES).await
}
async fn step_at(
    server: &mut Server,
    key: &mut Key,
    random: &mut Random,
    observer: &mut Observer,
    times: Times,
) -> Result<(), Failure> {
    match poll_fn(|cx| {
        server.poll_step_observed_at(
            cx,
            None,
            times,
            Ports {
                signer: key,
                entropy: random,
                store: &mut Store,
            },
            observer,
        )
    })
    .await?
    {
        Step::Progress => Ok(()),
        other => Err(format!("unexpected native step: {other:?}").into()),
    }
}
async fn during<T>(
    server: &mut Server,
    key: &mut Key,
    random: &mut Random,
    observer: &mut Observer,
    work: impl Future<Output = Result<T, Failure>>,
) -> Result<T, Failure> {
    during_at(server, key, random, observer, TIMES, work).await
}
async fn during_at<T>(
    server: &mut Server,
    key: &mut Key,
    random: &mut Random,
    observer: &mut Observer,
    times: Times,
    work: impl Future<Output = Result<T, Failure>>,
) -> Result<T, Failure> {
    async fn drive(
        server: &mut Server,
        key: &mut Key,
        random: &mut Random,
        observer: &mut Observer,
        times: Times,
    ) -> Result<(), Failure> {
        loop {
            step_at(server, key, random, observer, times).await?;
        }
    }
    let driving = drive(server, key, random, observer, times);
    tokio::select! {
        result = work => result,
        result = driving => { let _: () = result?; Err("native driver ended".into()) },
        () = tokio::time::sleep(Duration::from_secs(3)) => Err("native fixture timed out".into()),
    }
}
async fn until(
    server: &mut Server,
    key: &mut Key,
    random: &mut Random,
    observer: &mut Observer,
    ready: impl FnMut(&Server) -> bool,
) -> Result<(), Failure> {
    until_at(server, key, random, observer, TIMES, ready).await
}
async fn until_at(
    server: &mut Server,
    key: &mut Key,
    random: &mut Random,
    observer: &mut Observer,
    times: Times,
    mut ready: impl FnMut(&Server) -> bool,
) -> Result<(), Failure> {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready(server) {
            step_at(server, key, random, observer, times).await?;
        }
        Ok::<_, Failure>(())
    })
    .await?
}
async fn validated(
    server: &mut Server,
    key: &mut Key,
    remote: &Key,
    comm: &mut UnixStream,
    random: &mut Random,
    observer: &mut Observer,
) -> Result<(), Failure> {
    validated_characteristics(server, key, remote, comm, random, observer, 1).await
}
async fn validated_characteristics(
    server: &mut Server,
    key: &mut Key,
    remote: &Key,
    comm: &mut UnixStream,
    random: &mut Random,
    observer: &mut Observer,
    characteristics: u32,
) -> Result<(), Failure> {
    let mut register = frame(1211, 16);
    register[4..8].copy_from_slice(&characteristics.to_be_bytes());
    register[12..].copy_from_slice(b"tcp\0");
    comm.write_all(&register).await?;
    validated_queue(server, key, remote, comm, random, observer, (7, 32)).await
}
async fn validated_queue(
    server: &mut Server,
    key: &mut Key,
    remote: &Key,
    comm: &mut UnixStream,
    random: &mut Random,
    observer: &mut Observer,
    queue: (u32, u64),
) -> Result<(), Failure> {
    let (queue_id, grant) = queue;
    let previous = server.engine().snapshot().validations;
    let work = async {
        let mut queue = frame(1204, 74);
        queue[4..8].copy_from_slice(&queue_id.to_be_bytes());
        queue[8..40].copy_from_slice(&remote.identity().0);
        queue[44..48].copy_from_slice(&256u32.to_be_bytes());
        queue[48..56].copy_from_slice(&grant.to_be_bytes());
        queue[64..].copy_from_slice(b"tcp-local\0");
        comm.write_all(&queue).await?;
        loop {
            let output = read(comm).await?;
            if kind(&output) != 1209 {
                continue;
            }
            sent(comm, &output).await?;
            if output[16..48] != remote.identity().0 || kind(&output[48..]) != 1303 {
                continue;
            }
            let challenge = Challenge::decode(&output[48..])?;
            let validity = 1_000_000_000;
            let reply = Validation {
                nonce: challenge.nonce,
                origin: challenge.origin,
                validity,
                signature: *remote
                    .0
                    .sign(35, &Validation::signed_region(&challenge.nonce, validity))?
                    .as_bytes(),
            };
            comm.write_all(&incoming(remote.identity(), &reply.encode(), false))
                .await?;
            return Ok(());
        }
    };
    during(server, key, random, observer, work).await?;
    until(server, key, random, observer, |s| {
        s.dv_direct_queues(TIMES)
            .any(|q| q.peer() == remote.identity())
    })
    .await?;
    assert_eq!(server.engine().snapshot().validations, previous + 1);
    assert_eq!(server.engine().snapshot().attempts, 0);
    assert_eq!(server.engine().snapshot().outputs, 0);
    Ok(())
}

struct CancellationFixture {
    server: Server,
    key: Key,
    remote: Key,
    comm: UnixStream,
    random: Random,
    observer: Observer,
    source: Source,
}
impl CancellationFixture {
    async fn new() -> Result<Self, Failure> {
        Self::new_with_characteristics(1).await
    }
    async fn new_with_characteristics(characteristics: u32) -> Result<Self, Failure> {
        let mut key = Key(EddsaPrivateKey::from_seed([0x43; 32]));
        let remote = Key(EddsaPrivateKey::from_seed([0x47; 32]));
        let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 1, 262140)?;
        let (socket, mut comm) = UnixStream::pair()?;
        server.admit(Connection::from_unix(socket))?;
        let mut random = Random(0);
        let mut observer = Observer::default();
        validated_characteristics(
            &mut server,
            &mut key,
            &remote,
            &mut comm,
            &mut random,
            &mut observer,
            characteristics,
        )
        .await?;
        let source = server.dv_attach_source(key.identity())?;
        Ok(Self {
            server,
            key,
            remote,
            comm,
            random,
            observer,
            source,
        })
    }
    fn enqueue(&mut self, peer: PeerId, stamp: u64) -> Result<(TransferId, Vec<u8>), Failure> {
        self.enqueue_until(peer, stamp, Instant::now() + Duration::from_secs(2))
    }
    fn enqueue_until(
        &mut self,
        peer: PeerId,
        stamp: u64,
        hard: Instant,
    ) -> Result<(TransferId, Vec<u8>), Failure> {
        let queue = self
            .server
            .dv_direct_queues(TIMES)
            .find(|queue| queue.peer() == peer)
            .ok_or("no original validated peer queue")?;
        let bytes = learn(&self.key, stamp)?.to_vec();
        let transfer =
            self.server
                .dv_enqueue_output(&self.source, &queue, &bytes, true, hard, TIMES)?;
        self.observer.parent = Some(transfer.clone());
        Ok((transfer, bytes))
    }
    async fn retry(&mut self) -> Result<(), Failure> {
        poll_fn(|cx| {
            self.server.poll_retry_observed_at(
                cx,
                TIMES,
                &mut self.random,
                &mut Store,
                &mut self.observer,
            )
        })
        .await?;
        Ok(())
    }
    async fn hold_retry(&mut self) {
        self.observer.blocked = true;
        let pending = poll_fn(|cx| {
            Poll::Ready(self.server.poll_retry_observed_at(
                cx,
                TIMES,
                &mut self.random,
                &mut Store,
                &mut self.observer,
            ))
        })
        .await;
        assert!(
            pending.is_pending(),
            "observer did not retain the native output"
        );
    }
    async fn next_frame(&mut self, peer: PeerId, bytes: &[u8]) -> Result<Vec<u8>, Failure> {
        let work = async {
            loop {
                let output = read(&mut self.comm).await?;
                if kind(&output) == 1209 {
                    assert_eq!(&output[16..48], &peer.0);
                    // A canceled old1209 must never escape before this new one.
                    assert_eq!(&output[48..], bytes);
                    return Ok(output);
                }
            }
        };
        during(
            &mut self.server,
            &mut self.key,
            &mut self.random,
            &mut self.observer,
            work,
        )
        .await
    }
    async fn complete_next(&mut self, peer: PeerId, stamp: u64) -> Result<(), Failure> {
        self.observer.blocked = false;
        let (transfer, bytes) = self.enqueue(peer, stamp)?;
        // A blocked original retry may still own its one timer_step barrier.
        // Consume that barrier, then retry the new original once if necessary.
        self.retry().await?;
        if !self.server.dv_transfer_state(&transfer)?.queued {
            self.retry().await?;
        }
        assert!(self.server.dv_transfer_state(&transfer)?.queued);
        let output = self.next_frame(peer, &bytes).await?;
        sent(&mut self.comm, &output).await?;
        until(
            &mut self.server,
            &mut self.key,
            &mut self.random,
            &mut self.observer,
            |server| {
                server
                    .dv_transfer_state(&transfer)
                    .is_ok_and(|state| state.outcome == Some(TransferOutcome::Written))
            },
        )
        .await?;
        let state = self
            .server
            .dv_take_transfer(transfer)
            .map_err(|rejected| rejected.reason)?;
        assert!(state.queued && state.exposed && !state.job_pending);
        assert_eq!(state.outcome, Some(TransferOutcome::Written));
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Failure> {
        self.server.dv_begin_retire_source(&self.source)?;
        self.server.dv_retire_source(&self.source)?;
        self.server.shutdown()?;
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn unpumped_transfer_cancel_keeps_the_original_mq_and_next_parent_live() -> Result<(), Failure>
{
    let mut fixture = CancellationFixture::new().await?;
    let peer = fixture.remote.identity();
    let (transfer, _) = fixture.enqueue(peer, 37)?;
    assert_eq!(fixture.server.engine().snapshot().attempts, 0);
    fixture.server.dv_retire_transfer(&transfer)?;
    fixture.server.dv_retire_transfer(&transfer)?; // same transaction, no second retirement
    let state = fixture.server.dv_transfer_state(&transfer)?;
    assert!(!state.queued && !state.exposed && !state.job_pending);
    assert_eq!(state.outcome, Some(TransferOutcome::Unsent));
    fixture
        .server
        .dv_take_transfer(transfer)
        .map_err(|rejected| rejected.reason)?;
    assert!(fixture.server.take_native_retirement().is_none());
    assert_eq!(fixture.server.engine().snapshot().clients, 1);
    assert_eq!(fixture.server.engine().snapshot().queues, 1);
    fixture.complete_next(peer, 41).await?;
    assert!(fixture.server.take_native_retirement().is_none());
    fixture.finish()
}

#[tokio::test(flavor = "current_thread")]
async fn held_pre_native_transfer_cancel_removes_its_frame_but_keeps_another_peer_live()
-> Result<(), Failure> {
    let mut fixture = CancellationFixture::new().await?;
    let other = Key(EddsaPrivateKey::from_seed([0x53; 32]));
    validated_queue(
        &mut fixture.server,
        &mut fixture.key,
        &other,
        &mut fixture.comm,
        &mut fixture.random,
        &mut fixture.observer,
        (11, 32),
    )
    .await?;
    let (transfer, _) = fixture.enqueue(fixture.remote.identity(), 43)?;
    fixture.hold_retry().await;
    // The common Job minted a real SEND/Attempt; Server took its1209 but did
    // not admit it to Framed because the original observer refused readiness.
    assert_eq!(fixture.server.engine().snapshot().attempts, 1);
    assert_eq!(fixture.server.engine().snapshot().outputs, 0);
    let state = fixture.server.dv_transfer_state(&transfer)?;
    assert!(!state.queued && !state.exposed, "{state:?}");
    fixture.server.dv_retire_transfer(&transfer)?;
    fixture.server.dv_retire_transfer(&transfer)?;
    let state = fixture.server.dv_transfer_state(&transfer)?;
    assert!(!state.queued && !state.exposed && !state.job_pending);
    assert_eq!(state.outcome, Some(TransferOutcome::Unsent));
    fixture
        .server
        .dv_take_transfer(transfer)
        .map_err(|rejected| rejected.reason)?;
    assert_eq!(fixture.server.engine().snapshot().attempts, 0);
    assert_eq!(fixture.server.engine().snapshot().clients, 1);
    assert_eq!(fixture.server.engine().snapshot().queues, 2);
    assert!(fixture.server.take_native_retirement().is_none());
    fixture.complete_next(other.identity(), 47).await?;
    assert!(fixture.server.take_native_retirement().is_none());
    fixture.finish()
}

#[tokio::test(flavor = "current_thread")]
async fn original_native_deadline_cancels_held_transfer_without_retiring_its_mq()
-> Result<(), Failure> {
    let mut fixture = CancellationFixture::new().await?;
    let peer = fixture.remote.identity();
    // The fixed target predates original Job admission and the held1209. No
    // logical clock tick, new caller budget or native IO is needed to expire it.
    let hard = Instant::now() + Duration::from_millis(80);
    let (transfer, _) = fixture.enqueue_until(peer, 59, hard)?;
    fixture.hold_retry().await;
    assert_eq!(fixture.server.engine().snapshot().attempts, 1);
    let before = fixture.server.dv_transfer_state(&transfer)?;
    assert!(!before.queued && !before.exposed, "{before:?}");
    let event = tokio::time::timeout(
        Duration::from_secs(1),
        poll_fn(|cx| match fixture.server.poll_native_guard(cx) {
            Ok(Some(event)) => Poll::Ready(Ok::<_, Error>(event)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }),
    )
    .await??;
    assert!(Instant::now() >= hard);
    assert!(matches!(event, NativeGuardEvent::TransferUnsent(id) if id == transfer));
    let state = fixture.server.dv_transfer_state(&transfer)?;
    assert!(!state.queued && !state.exposed && !state.job_pending);
    assert_eq!(state.outcome, Some(TransferOutcome::Unsent));
    // Re-observing the same expired original does not create another event or
    // retire its communicator; the old absolute hard is never renewed.
    let repeated = poll_fn(|cx| Poll::Ready(fixture.server.poll_native_guard(cx))).await?;
    assert!(repeated.is_none());
    assert!(fixture.server.take_native_retirement().is_none());
    assert_eq!(fixture.server.engine().snapshot().clients, 1);
    assert_eq!(fixture.server.engine().snapshot().queues, 1);
    assert_eq!(fixture.server.engine().snapshot().attempts, 0);
    fixture
        .server
        .dv_take_transfer(transfer)
        .map_err(|rejected| rejected.reason)?;
    fixture.complete_next(peer, 61).await?;
    assert!(fixture.server.take_native_retirement().is_none());
    fixture.finish()
}

#[tokio::test(flavor = "current_thread")]
async fn native_admitted_cancel_retires_the_actual_mq_before_claiming_source_lost()
-> Result<(), Failure> {
    for whole_ipc in [false, true] {
        let mut fixture = CancellationFixture::new().await?;
        let peer = fixture.remote.identity();
        let (transfer, bytes) = fixture.enqueue(peer, 53)?;
        fixture.retry().await?;
        let admitted = fixture.server.dv_transfer_state(&transfer)?;
        assert!(admitted.queued && !admitted.exposed && admitted.outcome.is_none());
        assert_eq!(fixture.observer.queued, 1);
        assert_eq!(fixture.observer.exposed, 0);
        if whole_ipc {
            // Consume the real complete1209 but withhold its original1210.
            let original = fixture.next_frame(peer, &bytes).await?;
            assert_eq!(original.len(), 48 + bytes.len());
            let pending = fixture.server.dv_transfer_state(&transfer)?;
            assert!(pending.queued && pending.exposed && pending.outcome.is_none());
        }
        fixture.server.dv_retire_transfer(&transfer)?;
        assert_eq!(fixture.server.engine().snapshot().clients, 0);
        assert_eq!(fixture.comm.read(&mut [0; 1]).await?, 0);
        let retired = fixture
            .server
            .take_native_retirement()
            .ok_or("admitted cancellation did not record physical retirement")?;
        assert_eq!(retired.queued_frames > 0, !whole_ipc);
        fixture.server.dv_retire_transfer(&transfer)?;
        assert!(fixture.server.take_native_retirement().is_none());
        let state = fixture.server.dv_transfer_state(&transfer)?;
        assert!(state.queued && !state.job_pending);
        assert_eq!(state.exposed, whole_ipc);
        assert_eq!(state.outcome, Some(TransferOutcome::SourceLost));
        fixture
            .server
            .dv_take_transfer(transfer)
            .map_err(|rejected| rejected.reason)?;
        fixture.finish()?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn raw_dv_quarantine_does_not_block_its_same_mq_send_callback() -> Result<(), Failure> {
    let mut key = Key(EddsaPrivateKey::from_seed([0x13; 32]));
    let remote = Key(EddsaPrivateKey::from_seed([0x17; 32]));
    let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 1, 262140)?;
    let (socket, mut comm) = UnixStream::pair()?;
    let owner = server.admit(Connection::from_unix(socket))?;
    let mut random = Random(0);
    let mut observer = Observer::default();
    validated(
        &mut server,
        &mut key,
        &remote,
        &mut comm,
        &mut random,
        &mut observer,
    )
    .await?;
    // This is the explicit fixture source trust port, not an Actor/PILS proof.
    let source = server.dv_attach_source(key.identity())?;
    let queue = server
        .dv_direct_queues(TIMES)
        .next()
        .ok_or("no validated queue")?;
    let outbound = learn(&key, 19)?;
    let hard = Instant::now() + Duration::from_secs(2);
    let transfer = server.dv_enqueue_output(&source, &queue, &outbound, true, hard, TIMES)?;
    observer.parent = Some(transfer.clone());
    poll_fn(|cx| server.poll_retry_observed_at(cx, TIMES, &mut random, &mut Store, &mut observer))
        .await?;
    let work = async {
        loop {
            let output = read(&mut comm).await?;
            if kind(&output) != 1209 {
                assert_ne!(kind(&output), 1203);
                continue;
            }
            if output[48..] == outbound {
                return Ok(output);
            }
            sent(&mut comm, &output).await?;
        }
    };
    let original = during(&mut server, &mut key, &mut random, &mut observer, work).await?;
    let before = server.dv_transfer_state(&transfer)?;
    assert!(before.queued && before.exposed && before.outcome.is_none());
    assert_eq!(observer.queued, 1);
    assert!(observer.exposed >= original.len());
    let inbound = learn(&remote, 23)?;
    let mut sequence = incoming(remote.identity(), &inbound, true);
    let mut ack = frame(1210, 52);
    ack[4..8].copy_from_slice(&1u32.to_be_bytes());
    ack[8..16].copy_from_slice(&original[8..16]);
    ack[16..20].copy_from_slice(&original[4..8]);
    ack[20..].copy_from_slice(&original[16..48]);
    sequence.extend_from_slice(&ack);
    comm.write_all(&sequence).await?; // exact stream order: raw DV, THEN its original1210
    until(&mut server, &mut key, &mut random, &mut observer, |s| {
        s.dv_transfer_state(&transfer)
            .is_ok_and(|v| v.outcome == Some(TransferOutcome::Written))
    })
    .await?;
    let actual = server.dv_transfer_state(&transfer)?;
    assert!(actual.queued && actual.exposed && !actual.job_pending);
    assert_eq!(actual.outcome, Some(TransferOutcome::Written));
    server.dv_take_transfer(transfer).map_err(|r| r.reason)?;
    assert_eq!(server.engine().snapshot().clients, 1);
    assert_eq!(server.engine().snapshot().queues, 1);
    assert!(server.dv_source_accepting());
    assert!(server.take_native_retirement().is_none());
    let packet = server
        .dv_inbox()
        .ok_or("raw DV bypassed bounded quarantine")?;
    assert_eq!(packet.bytes, inbound);
    assert_eq!(packet.queue.owner(), &owner);
    assert_eq!(packet.id.source(), &source);
    let mut current = packet.id.clone();
    let until_original = packet.until;
    let absolute_original = packet.absolute_until;
    assert!(until_original.0 > TIMES.monotonic().0);
    assert!(until_original.0 <= TIMES.monotonic().0 + 10_000_000);
    let canonical = absolute_original.ok_or("raw input lost its original canonical target")?;
    assert_eq!(canonical.as_micros(), until_original.0);
    let schedule_original = server
        .dv_inbox_deadline()
        .ok_or("quarantine lost original target")?;
    assert_eq!(schedule_original, until_original);
    // Deliberately refuse original local admission. No Actor, signature result,
    // grant or FC completion is produced by these retries.
    for _ in 0..3 {
        let refused = server
            .dv_try_inbox_generic(&current, |_, origin, bytes| {
                assert_eq!(bytes, inbound);
                Err::<(), _>(origin)
            })?
            .err()
            .ok_or("unexpected admission")?;
        let stale = server
            .dv_finish_input(refused.original)
            .err()
            .ok_or("old refused origin acted again")?;
        assert_eq!(stale.reason, Error::Stale);
        current = refused.current;
        let retained = server.dv_inbox().ok_or("refusal lost original raw bytes")?;
        assert_eq!(retained.id.source(), &source);
        assert_eq!(retained.until, until_original);
        assert_eq!(retained.absolute_until, absolute_original);
        assert_eq!(retained.bytes, inbound);
        assert_eq!(server.dv_inbox_deadline(), Some(schedule_original));
        assert_eq!(server.dv_source_debts(&source), 1);
    }
    // Allow actual IO, while asserting no premature1203 for that held input.
    let quiet = async {
        let end = tokio::time::sleep(Duration::from_millis(20));
        tokio::pin!(end);
        loop {
            tokio::select! {
                () = &mut end => return Ok(()),
                result = read(&mut comm) => {
                    let output = result?;
                    assert_ne!(kind(&output), 1203, "quarantine fabricated FC completion");
                    if kind(&output) == 1209 { sent(&mut comm, &output).await?; }
                }
            }
        }
    };
    during(&mut server, &mut key, &mut random, &mut observer, quiet).await?;
    assert_eq!(
        server.dv_inbox().ok_or("quarantine disappeared")?.until,
        until_original
    );
    assert_eq!(server.dv_inbox_deadline(), Some(schedule_original));
    assert_eq!(server.dv_source_debts(&source), 1);
    server.dv_begin_retire_source(&source)?;
    assert!(server.dv_discard_unadmitted_source(&source)?);
    server.dv_retire_source(&source)?;
    assert_eq!(comm.read(&mut [0; 1]).await?, 0);
    let replacement = server.dv_attach_source(key.identity())?;
    assert_ne!(source, replacement);
    let called = Cell::new(false);
    let old = server.dv_try_inbox_generic(&current, |_, origin, _| {
        called.set(true);
        Err::<(), Ingress>(origin)
    });
    assert!(matches!(old, Err(Error::Stale)));
    assert!(!called.get());
    assert!(server.dv_inbox().is_none());
    server.dv_begin_retire_source(&replacement)?;
    server.dv_retire_source(&replacement)?;
    server.shutdown()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn partial_original_dv_source_closes_before_a_new_source_can_attach() -> Result<(), Failure> {
    let mut key = Key(EddsaPrivateKey::from_seed([0x31; 32]));
    let remote = Key(EddsaPrivateKey::from_seed([0x37; 32]));
    let mut server = Server::new(Engine::new(key.identity(), Limits::default())?, 1, 262140)?;
    let (socket, mut comm) = UnixStream::pair()?;
    server.admit(Connection::from_unix(socket))?;
    let mut random = Random(0);
    let mut observer = Observer::default();
    validated(
        &mut server,
        &mut key,
        &remote,
        &mut comm,
        &mut random,
        &mut observer,
    )
    .await?;
    let source = server.dv_attach_source(key.identity())?;
    let original = incoming(remote.identity(), &learn(&remote, 29)?, true);
    comm.write_all(&original[..1]).await?;
    // All prior output/attempts were drained by validation. The next native
    // progress is this actual first-byte read, still incomplete and source-bound.
    tokio::time::timeout(
        Duration::from_secs(1),
        step(&mut server, &mut key, &mut random, &mut observer),
    )
    .await??;
    assert!(server.dv_inbox().is_none());
    server.dv_begin_retire_source(&source)?;
    server.dv_retire_source(&source)?;
    assert_eq!(server.engine().snapshot().clients, 0);
    assert_eq!(comm.read(&mut [0; 1]).await?, 0);
    let replacement = server.dv_attach_source(key.identity())?;
    assert_ne!(source, replacement);
    assert!(comm.write_all(&original[1..]).await.is_err());
    assert!(server.dv_inbox().is_none());
    assert_eq!(server.dv_source_debts(&replacement), 0);
    server.dv_begin_retire_source(&replacement)?;
    server.dv_retire_source(&replacement)?;
    server.shutdown()?;
    Ok(())
}

fn opaque_fragmented_box() -> Result<Vec<u8>, Failure> {
    let mut bytes = vec![0; 512];
    dv::BoxHeader {
        without_fc: false,
        encapsulation: [0x71; 32],
        nonce: [0x72; 24],
        mac: [0x73; 16],
    }
    .encode(&[], &[0x74; 512 - dv::BOX_PREFIX], &mut bytes)?;
    assert_eq!(dv::BoxPacket::decode(&bytes)?.bytes(), bytes);
    Ok(bytes)
}
async fn complete_peer_at(
    fixture: &mut CancellationFixture,
    peer: PeerId,
    times: Times,
) -> Result<(), Failure> {
    let queue = fixture
        .server
        .dv_direct_queues(times)
        .find(|queue| queue.peer() == peer)
        .ok_or("no original next-peer queue")?;
    let bytes = learn(&fixture.key, 97)?.to_vec();
    let transfer = fixture.server.dv_enqueue_output(
        &fixture.source,
        &queue,
        &bytes,
        true,
        Instant::now() + Duration::from_secs(2),
        times,
    )?;
    fixture.observer.parent = Some(transfer.clone());
    poll_fn(|cx| {
        fixture.server.poll_retry_observed_at(
            cx,
            times,
            &mut fixture.random,
            &mut Store,
            &mut fixture.observer,
        )
    })
    .await?;
    let read_next = async {
        loop {
            let output = read(&mut fixture.comm).await?;
            if kind(&output) != 1209 {
                continue;
            }
            if output[48..] == bytes {
                assert_eq!(&output[16..48], &peer.0);
                sent(&mut fixture.comm, &output).await?;
                return Ok(());
            }
            // A tick may have emitted real FLOW maintenance. It cannot let an
            // old BOX/suffix masquerade as the new peer's message.
            gnunet_transport::p2p::Flow::decode(&output[48..])?;
            sent(&mut fixture.comm, &output).await?;
        }
    };
    during_at(
        &mut fixture.server,
        &mut fixture.key,
        &mut fixture.random,
        &mut fixture.observer,
        times,
        read_next,
    )
    .await?;
    until_at(
        &mut fixture.server,
        &mut fixture.key,
        &mut fixture.random,
        &mut fixture.observer,
        times,
        |server| {
            server
                .dv_transfer_state(&transfer)
                .is_ok_and(|s| s.outcome == Some(TransferOutcome::Written))
        },
    )
    .await?;
    let state = fixture
        .server
        .dv_take_transfer(transfer)
        .map_err(|r| r.reason)?;
    assert!(state.queued && state.exposed && !state.job_pending);
    assert_eq!(state.outcome, Some(TransferOutcome::Written));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn settled_partial_transfer_keeps_its_mq_but_a_missing_callback_still_retires_it()
-> Result<(), Failure> {
    // Explicit Engine times retire the business Job before its independent
    // original native target. Native write/1210 facts use real Unix IO below.
    const RETIRED_TIMES: Times = Times::shared_coordinate(1_000_100);
    for callback_received in [true, false] {
        let mut fixture = CancellationFixture::new().await?;
        let limited = Key(EddsaPrivateKey::from_seed([0x59; 32]));
        validated_queue(
            &mut fixture.server,
            &mut fixture.key,
            &limited,
            &mut fixture.comm,
            &mut fixture.random,
            &mut fixture.observer,
            (11, 2),
        )
        .await?;
        // Validation spent the first advertised packet grant. The remaining
        // single grant can expose only the first224B of this valid512B BOX.
        let queue = fixture
            .server
            .dv_direct_queues(TIMES)
            .find(|queue| queue.peer() == limited.identity())
            .ok_or("no limited original queue")?;
        let bytes = opaque_fragmented_box()?;
        let hard = Instant::now() + Duration::from_millis(200);
        let transfer = fixture.server.dv_enqueue_output(
            &fixture.source,
            &queue,
            &bytes,
            false,
            hard,
            TIMES,
        )?;
        fixture.observer.parent = Some(transfer.clone());
        fixture.retry().await?;
        let read_prefix = async {
            loop {
                let output = read(&mut fixture.comm).await?;
                if kind(&output) != 1209 {
                    continue;
                }
                assert_eq!(&output[16..48], &limited.identity().0);
                let fragment = gnunet_transport::p2p::Fragment::decode(&output[48..])?;
                assert_eq!(fragment.offset, 0);
                assert_eq!(fragment.total, 512);
                assert_eq!(fragment.body, &bytes[..224]);
                return Ok(output);
            }
        };
        let prefix = during(
            &mut fixture.server,
            &mut fixture.key,
            &mut fixture.random,
            &mut fixture.observer,
            read_prefix,
        )
        .await?;
        let exposed = fixture
            .server
            .dv_transfer_diagnostic(&transfer)
            .ok_or("lost original exposed transfer")?;
        assert!(exposed.state.queued && exposed.state.exposed && exposed.state.job_pending);
        assert_eq!(exposed.total_bytes, 512);
        assert_eq!(exposed.covered_bytes, 0);
        assert_eq!(exposed.live_chunks, 1);
        assert_eq!(
            exposed
                .job
                .ok_or("original suffix Job vanished")?
                .fresh_offset,
            224
        );
        assert_eq!(
            exposed
                .queue_state
                .ok_or("limited queue vanished")?
                .available,
            0
        );
        if callback_received {
            sent(&mut fixture.comm, &prefix).await?;
            until(
                &mut fixture.server,
                &mut fixture.key,
                &mut fixture.random,
                &mut fixture.observer,
                |server| {
                    server
                        .dv_transfer_diagnostic(&transfer)
                        .is_some_and(|d| d.covered_bytes == 224 && d.live_chunks == 0)
                },
            )
            .await?;
        }
        poll_fn(|cx| {
            fixture.server.poll_tick_observed_at(
                cx,
                RETIRED_TIMES,
                &mut fixture.random,
                &mut Store,
                &mut fixture.observer,
            )
        })
        .await?;
        let retired = fixture
            .server
            .dv_transfer_diagnostic(&transfer)
            .ok_or("business retirement lost original transfer")?;
        assert!(!retired.state.job_pending);
        assert!(retired.state.queued && retired.state.exposed);
        assert_eq!(retired.total_bytes, 512);
        assert_eq!(
            retired.covered_bytes,
            if callback_received { 224 } else { 0 }
        );
        assert_eq!(retired.live_chunks, usize::from(!callback_received));
        assert_eq!(
            retired.state.outcome,
            callback_received.then_some(TransferOutcome::Incomplete)
        );
        tokio::time::sleep_until(hard + Duration::from_millis(1)).await;
        let event = poll_fn(|cx| Poll::Ready(fixture.server.poll_native_guard(cx))).await?;
        if callback_received {
            assert!(!matches!(event, Some(NativeGuardEvent::SourceRetired(_))));
            assert!(fixture.server.take_native_retirement().is_none());
            assert_eq!(fixture.server.engine().snapshot().clients, 1);
            assert_eq!(fixture.server.engine().snapshot().queues, 2);
            let state = fixture
                .server
                .dv_take_transfer(transfer)
                .map_err(|r| r.reason)?;
            assert_eq!(state.outcome, Some(TransferOutcome::Incomplete));
            assert!(state.queued && state.exposed && !state.job_pending);
            // Same physical MQ, another real peer, without replaying the BOX.
            let other = fixture.remote.identity();
            complete_peer_at(&mut fixture, other, RETIRED_TIMES).await?;
            assert!(fixture.server.take_native_retirement().is_none());
        } else {
            assert!(matches!(event, Some(NativeGuardEvent::SourceRetired(_))));
            let closed = fixture
                .server
                .take_native_retirement()
                .ok_or("missing callback did not retain native retirement")?;
            assert!(matches!(&closed.cause, RetirementCause::DvDeadline {
                work: DvRetirementWork::Transfer { id, state }, ..
            } if *id == transfer && state.queued && state.exposed && state.outcome.is_none()));
            let before_close = closed
                .transfer
                .ok_or("missing original transfer snapshot")?;
            assert_eq!(before_close.peer, limited.identity());
            assert_eq!(before_close.queue, 11);
            assert!(before_close.client_live);
            assert_eq!(before_close.total_bytes, 512);
            assert_eq!(before_close.covered_bytes, 0);
            assert_eq!(before_close.live_chunks, 1);
            assert!(!before_close.state.job_pending);
            assert!(before_close.state.outcome.is_none());
            assert_eq!(fixture.server.engine().snapshot().clients, 0);
            // A wholly written maintenance frame may precede physical EOF.
            let mut tail = Vec::new();
            fixture.comm.read_to_end(&mut tail).await?;
            assert_eq!(fixture.comm.read(&mut [0; 1]).await?, 0);
            let state = fixture.server.dv_transfer_state(&transfer)?;
            assert_eq!(state.outcome, Some(TransferOutcome::SourceLost));
            fixture
                .server
                .dv_take_transfer(transfer)
                .map_err(|r| r.reason)?;
        }
        fixture.finish()?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn whole_local_write_waiting_for_remote_ack_retires_only_its_job_at_native_hard()
-> Result<(), Failure> {
    let mut fixture = CancellationFixture::new_with_characteristics(2).await?;
    let peer = fixture.remote.identity();
    let queue = fixture
        .server
        .dv_direct_queues(TIMES)
        .find(|queue| queue.peer() == peer)
        .ok_or("no original unreliable queue")?;
    let bytes = learn(&fixture.key, 101)?.to_vec();
    let hard = Instant::now() + Duration::from_millis(200);
    let transfer =
        fixture
            .server
            .dv_enqueue_output(&fixture.source, &queue, &bytes, true, hard, TIMES)?;
    fixture.observer.parent = Some(transfer.clone());
    fixture.retry().await?;
    let read_original = async {
        loop {
            let original = read(&mut fixture.comm).await?;
            if kind(&original) != 1209 {
                continue;
            }
            assert_eq!(&original[16..48], &peer.0);
            let reliable = gnunet_transport::p2p::Reliable::decode(&original[48..])?;
            assert_eq!(reliable.message, bytes);
            // This exact native1210 is intentionally the only acknowledgement.
            // The fixture never sends the reliability envelope's remote ACK.
            sent(&mut fixture.comm, &original).await?;
            return Ok(());
        }
    };
    during(
        &mut fixture.server,
        &mut fixture.key,
        &mut fixture.random,
        &mut fixture.observer,
        read_original,
    )
    .await?;
    until(
        &mut fixture.server,
        &mut fixture.key,
        &mut fixture.random,
        &mut fixture.observer,
        |server| {
            server
                .dv_transfer_state(&transfer)
                .is_ok_and(|state| state.outcome == Some(TransferOutcome::Written))
        },
    )
    .await?;
    let written = fixture
        .server
        .dv_transfer_diagnostic(&transfer)
        .ok_or("lost original local result")?;
    assert!(written.state.queued && written.state.exposed && written.state.job_pending);
    assert_eq!(written.covered_bytes, bytes.len());
    assert_eq!(written.total_bytes, bytes.len());
    assert_eq!(written.live_chunks, 0);
    assert_eq!(fixture.server.engine().snapshot().pending_remote_acks, 1);
    tokio::time::sleep_until(hard + Duration::from_millis(1)).await;
    let event = poll_fn(|cx| Poll::Ready(fixture.server.poll_native_guard(cx))).await?;
    assert!(matches!(event, Some(NativeGuardEvent::TransferSettled {
        id, outcome: TransferOutcome::Written,
    }) if id == transfer));
    assert!(fixture.server.take_native_retirement().is_none());
    assert_eq!(fixture.server.engine().snapshot().clients, 1);
    assert_eq!(fixture.server.engine().snapshot().queues, 1);
    assert_eq!(fixture.server.engine().snapshot().pending_remote_acks, 0);
    let settled = fixture
        .server
        .dv_take_transfer(transfer)
        .map_err(|r| r.reason)?;
    assert!(settled.queued && settled.exposed && !settled.job_pending);
    assert_eq!(settled.outcome, Some(TransferOutcome::Written));
    let repeated = poll_fn(|cx| Poll::Ready(fixture.server.poll_native_guard(cx))).await?;
    assert!(repeated.is_none());
    fixture.finish()
}
