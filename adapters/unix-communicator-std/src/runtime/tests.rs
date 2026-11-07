//! Component regression over real private Unix streams and datagrams. Identity
//! readiness in the recovery cases is a model precondition. The identity case
//! uses actual pure PILS generation and native announcements, without claiming
//! a normal PILS daemon or a C node.
use super::*;
use std::{
    os::unix::{ffi::OsStrExt, fs::DirBuilderExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixDatagram, UnixListener, UnixStream},
};

type Failure = Box<dyn std::error::Error>;
static NEXT: AtomicU64 = AtomicU64::new(0);
const PEER: [u8; 32] = [9; 32];
const OLD_MID: [u8; 8] = [0x81; 8];
const NEW_MID: [u8; 8] = [0x82; 8];

fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err("UNIX failed-send recovery regression".into())
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let path = PathBuf::from("/tmp").join(format!(
            "ucf-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Default)]
struct Trace {
    failures: usize,
    identities: Vec<[u8; 32]>,
    transport_losses: usize,
    retired: Vec<(u32, [u8; 8], SendOutcome, usize, bool)>,
}
impl Trace {
    fn observe(&mut self, event: Event<'_>) {
        match event {
            Event::Identity { peer, .. } => self.identities.push(peer),
            Event::TransportLost { .. } => self.transport_losses += 1,
            Event::SendError {
                retrying: false, ..
            } => self.failures += 1,
            Event::SendRetired {
                queue,
                message_id,
                outcome,
                ack_bytes,
                ack_written,
                ..
            } => self
                .retired
                .push((queue, message_id, outcome, ack_bytes, ack_written)),
            _ => {}
        }
    }
}
fn frame(kind: u16, size: usize) -> Result<Vec<u8>, Failure> {
    let mut value = vec![0; size];
    gnunet_wire::official::MessageHeader::from_total_size(
        gnunet_wire::official::MessageType::new(kind),
        size,
    )?
    .encode(&mut value)?;
    Ok(value)
}
fn create(address: &Path) -> Result<Vec<u8>, Failure> {
    let view = gnunet_unix_communicator::Address::from_path(address.as_os_str().as_bytes())?;
    let mut value = frame(1206, 41 + view.encoded_len()?)?;
    value[4..8].copy_from_slice(&[1, 2, 3, 4]);
    value[8..40].copy_from_slice(&PEER);
    view.encode(&mut value[40..])?;
    Ok(value)
}
fn send(queue: u32, mid: [u8; 8], message: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut value = frame(1209, 48 + message.len())?;
    value[4..8].copy_from_slice(&queue.to_be_bytes());
    value[8..16].copy_from_slice(&mid);
    value[16..48].copy_from_slice(&PEER);
    value[48..].copy_from_slice(message);
    Ok(value)
}
async fn read_frame(service: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut head = [0; 4];
    service.read_exact(&mut head).await?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    check(size >= 4)?;
    let mut value = vec![0; size];
    value[..4].copy_from_slice(&head);
    service.read_exact(&mut value[4..]).await?;
    Ok(value)
}
async fn input(runtime: &mut Runtime<'_>, trace: &mut Trace) -> Result<(), Failure> {
    while runtime
        .transport
        .framing()
        .is_none_or(|f| f.frame().is_none())
    {
        let now = runtime.clock.sample()?.now.as_micros();
        poll_fn(|cx| runtime.poll_read(cx, now, &mut |event| trace.observe(event))).await?;
    }
    Ok(())
}
async fn flush(runtime: &mut Runtime<'_>, trace: &mut Trace) -> Result<(), Failure> {
    while !runtime.outputs.is_empty() {
        poll_fn(|cx| runtime.poll_write(cx, &mut |event| trace.observe(event))).await?;
    }
    Ok(())
}
fn queue_id(value: &[u8]) -> Result<u32, Failure> {
    match Request::decode(value)? {
        Request::QueueSetup(queue, _) => Ok(queue.id),
        _ => Err("expected real QueueSetup frame".into()),
    }
}
fn ack(value: &[u8], queue: u32, mid: [u8; 8], expected: i32) -> Result<(), Failure> {
    check(matches!(Request::decode(value)?, Request::Sent {
        queue: q, message_id, peer: PEER, status
    } if q == queue && message_id == mid && status == expected))
}
fn ready_precondition(runtime: &mut Runtime<'_>) {
    runtime.peer = Some([7; 32]);
    runtime.registered = true;
    runtime.address_written = true;
    runtime.ever_ready = true;
    runtime.restoring = false;
}

async fn recovery(disconnect: bool) -> Result<(), Failure> {
    let dir = Directory::new()?;
    let destination = dir.0.join("missing");
    let service_path = dir.0.join("transport");
    let listener = UnixListener::bind(&service_path)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(gnunet_service_runtime::clock::SystemClock);
    let instance = Instance::new();
    let mut pils_instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::bind(
        &instance,
        &mut pils_instance,
        Sources {
            transport: EndpointSource::unix_with_clock(service_path, clock.clone()),
            pils: EndpointSource::unix_with_clock(dir.0.join("unused-pils"), clock),
        },
        dir.0.join("native").as_os_str().as_bytes(),
        Limits {
            queues: 2,
            incoming: 2,
            io_slice: 7, // Exercise actual partial result ACK writes.
            ..Limits::default()
        },
    )?;
    let mut trace = Trace::default();
    poll_fn(|cx| runtime.poll_connect(cx, &mut |event| trace.observe(event))).await?;
    let (mut service, _) = listener.accept().await?;
    ready_precondition(&mut runtime);
    let create = create(&destination)?;
    service.write_all(&create).await?;
    input(&mut runtime, &mut trace).await?;
    let now = runtime.clock.sample()?.now.as_micros();
    check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    flush(&mut runtime, &mut trace).await?;
    let old = queue_id(&read_frame(&mut service).await?)?;
    check(matches!(
        Request::decode(&read_frame(&mut service).await?)?,
        Request::Created(_, true)
    ))?;

    service
        .write_all(&send(old, OLD_MID, &[0, 5, 0, 0, 0x11])?)
        .await?;
    input(&mut runtime, &mut trace).await?;
    check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    // The destination does not exist: the actual kernel produces the failure.
    poll_fn(|cx| runtime.poll_send(cx, now, &mut |event| trace.observe(event))).await?;
    check(trace.failures == 1 && runtime.statistics().bytes_sent == 0)?;
    runtime.restoring = true;
    check(runtime.send_results(now, &mut |event| trace.observe(event))?)?;
    check(runtime.outputs.back().is_some_and(|output| {
        matches!(output.role, Role::SendDown(q) if q == old)
            && runtime.restore_fence == output.id.serial
    }))?;

    service
        .write_all(&send(old, [0x83; 8], &[0, 4, 0, 0])?)
        .await?;
    input(&mut runtime, &mut trace).await?;
    check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    service.write_all(&create).await?;
    input(&mut runtime, &mut trace).await?;
    let original_rx = runtime.rx.ok_or("missing original RX bound")?;
    check(!runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    check(
        runtime
            .rx
            .is_some_and(|bound| bound.hard == original_rx.hard),
    )?;

    poll_fn(|cx| runtime.poll_write(cx, &mut |event| trace.observe(event))).await?;
    check(runtime.statistics().queues == 1 && trace.retired.is_empty())?;
    if disconnect {
        // A real broken stream while the original ACK is only partially sent.
        drop(service);
        while runtime.epoch.is_some() {
            check(!runtime.outputs.is_empty())?;
            poll_fn(|cx| runtime.poll_write(cx, &mut |event| trace.observe(event))).await?;
        }
        check(runtime.statistics().queues == 0 && runtime.outputs.is_empty())?;
        poll_fn(|cx| runtime.poll_connect(cx, &mut |event| trace.observe(event))).await?;
        let (replacement, _) = listener.accept().await?;
        service = replacement;
        ready_precondition(&mut runtime);
        // The old held CREATE was retired, not replayed on this stream.
        service.write_all(&create).await?;
        input(&mut runtime, &mut trace).await?;
    } else {
        flush(&mut runtime, &mut trace).await?;
        ack(&read_frame(&mut service).await?, old, OLD_MID, -1)?;
        check(matches!(Request::decode(&read_frame(&mut service).await?)?,
            Request::QueueDown(q, PEER) if q == old))?;
        ack(&read_frame(&mut service).await?, old, [0x83; 8], 0)?;
        check(runtime.statistics().queues == 0)?;
        check(
            runtime
                .rx
                .is_some_and(|bound| bound.hard == original_rx.hard),
        )?;
    }
    check(trace.retired.len() == 1)?;
    let &(q, mid, outcome, ack_bytes, ack_written) = trace
        .retired
        .first()
        .ok_or("missing failed-send retirement")?;
    check(q == old && mid == OLD_MID && matches!(outcome, SendOutcome::Failed { .. }))?;
    check(if disconnect {
        (7..52).contains(&ack_bytes)
    } else {
        ack_bytes == 52
    })?;
    check(ack_written != disconnect)?;
    check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    flush(&mut runtime, &mut trace).await?;
    let fresh = queue_id(&read_frame(&mut service).await?)?;
    check(fresh != old)?;
    check(matches!(
        Request::decode(&read_frame(&mut service).await?)?,
        Request::Created(_, true)
    ))?;

    let destination = UnixDatagram::bind(destination)?;
    let message = [0, 5, 0, 0, 0x22];
    service.write_all(&send(fresh, NEW_MID, &message)?).await?;
    input(&mut runtime, &mut trace).await?;
    check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    poll_fn(|cx| runtime.poll_send(cx, now, &mut |event| trace.observe(event))).await?;
    check(runtime.send_results(now, &mut |event| trace.observe(event))?)?;
    flush(&mut runtime, &mut trace).await?;
    ack(&read_frame(&mut service).await?, fresh, NEW_MID, 1)?;
    check(matches!(Request::decode(&read_frame(&mut service).await?)?,
        Request::QueueUpdate(q) if q.id == fresh && q.length == 1))?;
    let mut packet = [0; 128];
    let size = destination.recv(&mut packet).await?;
    check(
        gnunet_unix_communicator::Datagram::decode(&packet[..size], runtime.mtu)?.message
            == message,
    )?;
    check(
        destination
            .try_recv(&mut packet)
            .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock),
    )?;
    let closed = runtime.close(&mut |event| trace.observe(event));
    check(!closed.uncertain())?;
    Ok(())
}

#[test]
fn failed_native_send_retires_queue_and_recreates_without_replaying() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), recovery(false)).await? })
}

#[test]
fn source_loss_during_negative_ack_does_not_reannounce_failed_queue() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), recovery(true)).await? })
}

async fn identity(runtime: &mut Runtime<'_>, trace: &mut Trace) -> Result<(), Failure> {
    let observations = trace.identities.len();
    while trace.identities.len() == observations {
        let now = runtime.clock.sample()?.now.as_micros();
        poll_fn(|cx| runtime.poll_pils(cx, now, &mut |event| trace.observe(event))).await?;
    }
    Ok(())
}
fn conditional_update(
    service: &mut gnunet_pils::Service<4096>,
    address: &[u8],
    now: u64,
) -> Result<(), Failure> {
    use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
    use gnunet_hello::{HelloBuilder, Limits as HelloLimits};
    let limits = HelloLimits {
        maximum_input_bytes: 4096,
        maximum_address_bytes: 2048,
        maximum_addresses: 16,
    };
    let mut addresses = [0; 2048];
    let mut builder = HelloBuilder::new(&mut addresses, limits);
    builder.add_address(address)?;
    // FEED is an unsigned address container. The actual pure PILS service,
    // rather than this caller, derives and signs the next public identity.
    let hello = builder.with_signature(
        EddsaPublicKey::from_bytes([0; 32]),
        EddsaSignature::from_bytes([0; 64]),
        gnunet_types::AbsoluteTime::from_micros(now),
    );
    let mut block = vec![0; hello.block_len()?];
    hello.encode_block(&mut block)?;
    let mut frame = vec![0; block.len() + 8];
    gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut frame)?;
    let mut scratch = [0; 2048];
    let mut output = [0; 4096];
    check(matches!(
        service.receive(&frame, &mut scratch, now, &mut output)?,
        gnunet_pils::Action::Broadcast {
            identity_changed: true
        }
    ))
}
async fn changed_identity_preserves_original_packet_and_exposed_ack() -> Result<(), Failure> {
    use gnunet_pils::{MasterKey, Profile, Service};
    let dir = Directory::new()?;
    let transport_path = dir.0.join("transport");
    let pils_path = dir.0.join("pils");
    let transport_listener = UnixListener::bind(&transport_path)?;
    let pils_listener = UnixListener::bind(&pils_path)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(gnunet_service_runtime::clock::SystemClock);
    let now = clock.sample()?.now.as_micros();
    let instance = Instance::new();
    let mut pils_instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::bind(
        &instance,
        &mut pils_instance,
        Sources {
            transport: EndpointSource::unix_with_clock(transport_path, clock.clone()),
            pils: EndpointSource::unix_with_clock(pils_path, clock),
        },
        dir.0.join("native").as_os_str().as_bytes(),
        Limits {
            queues: 2,
            incoming: 2,
            io_slice: 7,
            profile: Profile::ReferenceDeterministic,
            ..Limits::default()
        },
    )?;
    let mut producer = Service::<4096>::new(
        MasterKey::from_seed([67; 32]),
        Profile::ReferenceDeterministic,
        now,
        gnunet_hello::Limits {
            maximum_input_bytes: 4096,
            maximum_address_bytes: 2048,
            maximum_addresses: 16,
        },
    )?;
    let a = *producer.identity().public_key().as_bytes();
    let mut trace = Trace::default();
    poll_fn(|cx| runtime.poll_connect(cx, &mut |event| trace.observe(event))).await?;
    let (mut transport, _) = transport_listener.accept().await?;
    // Connect the real PILS MQ; it has no invented INIT or identity precondition.
    while runtime.pils.epoch().is_none() {
        poll_fn(|cx| runtime.poll_pils(cx, now, &mut |event| trace.observe(event))).await?;
    }
    let (mut pils, _) = pils_listener.accept().await?;
    pils.write_all(producer.announcement()).await?;
    identity(&mut runtime, &mut trace).await?;
    check(runtime.peer == Some(a))?;
    check(runtime.setup(now, &mut |event| trace.observe(event))?)?;
    flush(&mut runtime, &mut trace).await?;
    check(matches!(
        Request::decode(&read_frame(&mut transport).await?)?,
        Request::Register { .. }
    ))?;
    check(matches!(
        Request::decode(&read_frame(&mut transport).await?)?,
        Request::AddAddress { .. }
    ))?;
    check(runtime.ready())?;
    let first_path = dir.0.join("first");
    let second_path = dir.0.join("second");
    let first = UnixDatagram::bind(&first_path)?;
    let second = UnixDatagram::bind(&second_path)?;
    let mut queues = [0; 2];
    for (slot, path) in queues.iter_mut().zip([&first_path, &second_path]) {
        transport.write_all(&create(path)?).await?;
        input(&mut runtime, &mut trace).await?;
        check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
        flush(&mut runtime, &mut trace).await?;
        *slot = queue_id(&read_frame(&mut transport).await?)?;
        check(matches!(
            Request::decode(&read_frame(&mut transport).await?)?,
            Request::Created(_, true)
        ))?;
    }
    // One real SEND is completely written to the network but its original ACK
    // has a positive short stream prefix. A different SEND remains unsent.
    transport
        .write_all(&send(queues[1], NEW_MID, &[0, 5, 0, 0, 0x12])?)
        .await?;
    input(&mut runtime, &mut trace).await?;
    check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    poll_fn(|cx| runtime.poll_send(cx, now, &mut |event| trace.observe(event))).await?;
    let mut packet = [0; 2048];
    let length = second.recv(&mut packet).await?;
    check(
        gnunet_unix_communicator::Datagram::decode(&packet[..length], runtime.mtu)?.claimed_sender
            == a,
    )?;
    check(runtime.send_results(now, &mut |event| trace.observe(event))?)?;
    poll_fn(|cx| runtime.poll_write(cx, &mut |event| trace.observe(event))).await?;
    let output = runtime
        .outputs
        .front()
        .ok_or("missing partial original ACK")?;
    check(
        output.bytes > 0
            && !runtime
                .queues
                .iter()
                .flatten()
                .find(|q| q.id == queues[1])
                .and_then(|q| q.send.as_ref())
                .ok_or("missing original whole send")?
                .ack_written,
    )?;
    let original_ack = (
        output.id,
        output.bytes,
        output.bound.until,
        output.bound.hard,
    );
    transport
        .write_all(&send(queues[0], OLD_MID, &[0, 5, 0, 0, 0x11])?)
        .await?;
    input(&mut runtime, &mut trace).await?;
    check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    let queue = runtime
        .queues
        .iter()
        .flatten()
        .find(|q| q.id == queues[0])
        .ok_or("missing unsent queue")?;
    let pending = queue
        .send
        .as_ref()
        .ok_or("missing unsent original packet")?;
    check(pending.outcome == SendOutcome::Unsent)?;
    let original = (
        pending.packet.as_ptr(),
        pending.bound.until,
        pending.bound.hard,
        queue.idle.until,
        queue.idle.hard,
        queue.source,
    );
    let epoch = runtime.epoch;
    let socket = runtime.socket_epoch;
    let parent = (
        runtime.parent.until,
        runtime.parent.hard,
        runtime.startup.until,
        runtime.startup.hard,
    );
    let pils_epoch = runtime.pils.epoch();
    conditional_update(&mut producer, b"unix:///changed-address", now)?;
    let b = *producer.identity().public_key().as_bytes();
    check(a != b)?;
    pils.write_all(producer.announcement()).await?;
    identity(&mut runtime, &mut trace).await?;
    check(
        runtime.peer == Some(b)
            && runtime.ready()
            && runtime.epoch == epoch
            && runtime.socket_epoch == socket
            && runtime.pils.epoch() == pils_epoch,
    )?;
    check(
        (
            runtime.parent.until,
            runtime.parent.hard,
            runtime.startup.until,
            runtime.startup.hard,
        ) == parent,
    )?;
    let queue = runtime
        .queues
        .iter()
        .flatten()
        .find(|q| q.id == queues[0])
        .ok_or("missing retained queue")?;
    let pending = queue
        .send
        .as_ref()
        .ok_or("missing retained original packet")?;
    check(
        (
            pending.packet.as_ptr(),
            pending.bound.until,
            pending.bound.hard,
            queue.idle.until,
            queue.idle.hard,
            queue.source,
        ) == original,
    )?;
    check(
        gnunet_unix_communicator::Datagram::decode(&pending.packet, runtime.mtu)?.claimed_sender
            == a,
    )?;
    let output = runtime
        .outputs
        .front()
        .ok_or("missing retained exposed ACK")?;
    check(
        (
            output.id,
            output.bytes,
            output.bound.until,
            output.bound.hard,
        ) == original_ack,
    )?;
    check(trace.transport_losses == 0 && trace.retired.is_empty())?;
    // Same-PID announcements also leave the physical owners and original debts.
    pils.write_all(producer.announcement()).await?;
    identity(&mut runtime, &mut trace).await?;
    check(runtime.epoch == epoch && runtime.pils.epoch() == pils_epoch && runtime.ready())?;
    flush(&mut runtime, &mut trace).await?;
    ack(&read_frame(&mut transport).await?, queues[1], NEW_MID, 1)?;
    check(matches!(
        Request::decode(&read_frame(&mut transport).await?)?,
        Request::QueueUpdate(_)
    ))?;
    poll_fn(|cx| runtime.poll_send(cx, now, &mut |event| trace.observe(event))).await?;
    let length = first.recv(&mut packet).await?;
    let actual = gnunet_unix_communicator::Datagram::decode(&packet[..length], runtime.mtu)?;
    check(actual.claimed_sender == a && actual.message == [0, 5, 0, 0, 0x11])?;
    check(runtime.send_results(now, &mut |event| trace.observe(event))?)?;
    flush(&mut runtime, &mut trace).await?;
    ack(&read_frame(&mut transport).await?, queues[0], OLD_MID, 1)?;
    check(matches!(
        Request::decode(&read_frame(&mut transport).await?)?,
        Request::QueueUpdate(_)
    ))?;
    transport
        .write_all(&send(queues[0], NEW_MID, &[0, 5, 0, 0, 0x13])?)
        .await?;
    input(&mut runtime, &mut trace).await?;
    check(runtime.dispatch(now, &mut |event| trace.observe(event))?)?;
    poll_fn(|cx| runtime.poll_send(cx, now, &mut |event| trace.observe(event))).await?;
    let length = first.recv(&mut packet).await?;
    let actual = gnunet_unix_communicator::Datagram::decode(&packet[..length], runtime.mtu)?;
    check(actual.claimed_sender == b && actual.message == [0, 5, 0, 0, 0x13])?;
    check(runtime.send_results(now, &mut |event| trace.observe(event))?)?;
    flush(&mut runtime, &mut trace).await?;
    ack(&read_frame(&mut transport).await?, queues[0], NEW_MID, 1)?;
    check(matches!(
        Request::decode(&read_frame(&mut transport).await?)?,
        Request::QueueUpdate(_)
    ))?;
    check(
        runtime.epoch == epoch
            && runtime.socket_epoch == socket
            && trace.transport_losses == 0
            && trace.retired.is_empty(),
    )?;
    check(
        first
            .try_recv(&mut packet)
            .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock),
    )?;
    check(
        second
            .try_recv(&mut packet)
            .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock),
    )?;
    // Only actual EOF is a lost PILS source; a valid PID update above was not.
    drop(pils);
    let result = loop {
        match poll_fn(|cx| runtime.poll_pils(cx, now, &mut |event| trace.observe(event))).await {
            Ok(()) => {}
            Err(error) => break error,
        }
    };
    check(matches!(result, Fault::IdentityLost))?;
    check(!runtime.close(&mut |event| trace.observe(event)).uncertain())?;
    Ok(())
}
#[test]
fn verified_identity_change_keeps_original_packets_and_ack_debt_on_same_mq() -> Result<(), Failure>
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(8),
                changed_identity_preserves_original_packet_and_exposed_ack(),
            )
            .await?
        })
}
