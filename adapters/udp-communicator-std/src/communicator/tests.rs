//! Real private IPC/loopback components, not a normal or unchanged-C node.
use super::*;
use gnunet_wire::official::{MessageHeader, MessageType, communicator::Request};
use std::{
    cell::Cell,
    future::poll_fn,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UdpSocket, UnixStream},
};

type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
fn check(value: bool) -> Test {
    if value {
        Ok(())
    } else {
        Err("UDP generation retirement regression".into())
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, io::Error> {
        let path = std::env::temp_dir().join(format!(
            "udp-generation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
struct Random<'a>(&'a Cell<bool>);
impl Entropy for Random<'_> {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        if self.0.get() {
            Err(Error::Entropy)
        } else {
            getrandom::fill(bytes).map_err(|_| Error::Entropy)
        }
    }
}
fn frame(kind: u16, size: usize) -> Result<Vec<u8>, Error> {
    let mut value = vec![0; size];
    MessageHeader::from_total_size(MessageType::new(kind), size)?.encode(&mut value)?;
    Ok(value)
}
fn create(peer: PeerId, target: SocketAddr) -> Result<Vec<u8>, Error> {
    let address = transport::address(target);
    let mut value = frame(1206, 41 + address.len())?;
    value[4..8].copy_from_slice(&[1, 2, 3, 4]);
    value[8..40].copy_from_slice(&peer);
    value[40..40 + address.len()].copy_from_slice(address.as_bytes());
    Ok(value)
}
fn send(peer: PeerId, queue: u32, mid: [u8; 8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let mut value = frame(1209, 48 + message.len())?;
    value[4..8].copy_from_slice(&queue.to_be_bytes());
    value[8..16].copy_from_slice(&mid);
    value[16..48].copy_from_slice(&peer);
    value[48..].copy_from_slice(message);
    Ok(value)
}
async fn read_frame(service: &mut UnixStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut head = [0; 4];
    service.read_exact(&mut head).await?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    check(size >= 4)?;
    let mut value = vec![0; size];
    value[..4].copy_from_slice(&head);
    service.read_exact(&mut value[4..]).await?;
    Ok(value)
}
fn ack(value: &[u8], peer: PeerId, queue: u32, mid: [u8; 8], success: bool) -> Test {
    check(matches!(Request::decode(value)?, Request::Sent {
        queue: q, message_id, peer: p, status
    } if q == queue && message_id == mid && p == peer && status == if success { 1 } else { -1 }))
}
fn setup(value: &[u8]) -> Result<u32, Box<dyn std::error::Error>> {
    match Request::decode(value)? {
        Request::QueueSetup(queue, _) => Ok(queue.id),
        _ => Err("expected actual QueueSetup".into()),
    }
}
fn owner(
    local: &Identity,
) -> Result<(Communicator<'static>, UnixStream), Box<dyn std::error::Error>> {
    let socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
    let policy = socket.profile().sender_policy();
    let (service, stream) = UnixStream::pair()?;
    let communicator = Communicator::new(
        Connection::from_unix(stream),
        vec![socket],
        Configuration {
            local: local.peer(),
            peers: 2,
            endpoints: 2,
            capacity: Capacity {
                frames: 4,
                bytes: 65535,
                io_slice: 7,
            },
            transmit: policy,
        },
        100,
    )?;
    Ok((communicator, service))
}
async fn drain(owner: &mut Communicator<'_>) -> Test {
    while !owner.effects.is_empty() || owner.pending_mq.is_some() {
        poll_fn(|cx| owner.poll_publications(cx)).await?;
    }
    Ok(())
}
async fn drive(
    owner: &mut Communicator<'_>,
    local: &Identity,
    journal: &mut Journal,
    reject_entropy: &Cell<bool>,
    sent: &Cell<usize>,
) -> Test {
    loop {
        let event = poll_fn(|cx| {
            owner.poll_step(
                cx,
                local,
                journal,
                100,
                &mut Random(reject_entropy),
                &mut |_| Ok(1),
            )
        })
        .await?;
        if matches!(event, Activity::NativeSent { .. }) {
            sent.set(sent.get() + 1);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn failed_box_send_withdraws_both_queues_and_recreates_without_old_credit() -> Test {
    tokio::time::timeout(Duration::from_secs(5), async {
        let scratch = Scratch::new()?;
        let local = Identity::from_seed([3; 32]);
        let remote = Identity::from_seed([5; 32]);
        let destination = UdpSocket::bind("127.0.0.1:0").await?;
        let target = destination.local_addr()?;
        let (mut owner, mut service) = owner(&local)?;
        let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
        let reject_entropy = Cell::new(false);
        let sent = Cell::new(0usize);
        let scenario = async {
            check(matches!(
                Request::decode(&read_frame(&mut service).await?)?,
                Request::Register { .. }
            ))?;
            let create = create(remote.peer(), target)?;
            service.write_all(&create).await?;
            let kx = setup(&read_frame(&mut service).await?)?;
            check(matches!(
                Request::decode(&read_frame(&mut service).await?)?,
                Request::Created(_, true)
            ))?;
            let first = [0, 5, 0, 0, 0x11];
            service
                .write_all(&send(remote.peer(), kx, [1; 8], &first)?)
                .await?;
            ack(
                &read_frame(&mut service).await?,
                remote.peer(),
                kx,
                [1; 8],
                true,
            )?;
            let mut packet = [0; 2048];
            let size = destination.recv(&mut packet).await?;
            let mut scratch = [0; 2048];
            let opened = handshake::open(&remote, &packet[..size], &mut scratch)?;
            check(opened.sender() == local.peer())?;
            check(
                gnunet_udp_communicator_core::wire::Body::decode(opened.body())?.message
                    == Some(&first),
            )?;
            let grant = Ack {
                allowed: 4,
                cmac: *opened.cmac().ok_or("missing actual KX CMAC")?,
            };
            drop(opened);
            let mut notification = frame(1220, 112)?;
            notification[8..40].copy_from_slice(&remote.peer());
            grant.encode(&mut notification[40..])?;
            service.write_all(&notification).await?;
            let boxed = setup(&read_frame(&mut service).await?)?;
            check(boxed != kx)?;

            reject_entropy.set(true);
            service
                .write_all(&send(remote.peer(), boxed, [2; 8], &[0, 5, 0, 0, 0x22])?)
                .await?;
            ack(
                &read_frame(&mut service).await?,
                remote.peer(),
                boxed,
                [2; 8],
                false,
            )?;
            check(matches!(Request::decode(&read_frame(&mut service).await?)?,
                Request::QueueDown(q, p) if q == kx && p == remote.peer()))?;
            check(matches!(Request::decode(&read_frame(&mut service).await?)?,
                Request::QueueDown(q, p) if q == boxed && p == remote.peer()))?;
            reject_entropy.set(false);
            // A duplicate old CMAC cannot grant credit to a replacement sender.
            service.write_all(&notification).await?;
            service.write_all(&create).await?;
            let fresh = setup(&read_frame(&mut service).await?)?;
            check(fresh > boxed)?;
            check(matches!(
                Request::decode(&read_frame(&mut service).await?)?,
                Request::Created(_, true)
            ))?;
            // The old QID's failure must not retire the new generation.
            service
                .write_all(&send(remote.peer(), boxed, [3; 8], &[0, 4, 0, 0])?)
                .await?;
            ack(
                &read_frame(&mut service).await?,
                remote.peer(),
                boxed,
                [3; 8],
                false,
            )?;
            let next = [0, 5, 0, 0, 0x33];
            service
                .write_all(&send(remote.peer(), fresh, [4; 8], &next)?)
                .await?;
            ack(
                &read_frame(&mut service).await?,
                remote.peer(),
                fresh,
                [4; 8],
                true,
            )?;
            let size = destination.recv(&mut packet).await?;
            let opened = handshake::open(&remote, &packet[..size], &mut scratch)?;
            check(opened.sender() == local.peer())?;
            check(
                gnunet_udp_communicator_core::wire::Body::decode(opened.body())?.message
                    == Some(&next),
            )?;
            check(
                destination
                    .try_recv(&mut packet)
                    .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock),
            )?;
            Ok::<(), Box<dyn std::error::Error>>(())
        };
        tokio::select! {
            result = drive(&mut owner, &local, &mut journal, &reject_entropy, &sent) => result?,
            result = scenario => result?,
        }
        check(sent.get() == 2 && owner.endpoints() == 1)?;
        owner.close();
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn retiring_endpoint_input_is_consumed_without_replay_commit_then_can_be_received() -> Test {
    tokio::time::timeout(Duration::from_secs(5), async {
        let scratch = Scratch::new()?;
        let local = Identity::from_seed([3; 32]);
        let remote = Identity::from_seed([5; 32]);
        let destination = UdpSocket::bind("127.0.0.1:0").await?;
        let target = destination.local_addr()?;
        let (mut owner, _service) = owner(&local)?;
        let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
        drain(&mut owner).await?;
        let EndpointAdmission::New(plan) =
            owner.prepare_endpoint(remote.peer(), target, 100, &mut |_| Ok(1))?
        else {
            return Err("expected new endpoint".into());
        };
        let old = plan.endpoint.kx;
        let index = plan.index;
        owner.commit_endpoint(plan)?;
        drain(&mut owner).await?;
        owner.fail_endpoint_send(
            index,
            frozen(52, |out| {
                transport::sent(old, [1; 8], remote.peer(), false, out)
            })?,
        )?;
        drain(&mut owner).await?;
        check(matches!(
            owner.prepare_endpoint(remote.peer(), target, 100, &mut |_| Ok(1))?,
            EndpointAdmission::Retiring
        ))?;
        check(matches!(
            owner.prepare_endpoint_on(remote.peer(), target, 0, 100, &mut |_| Ok(1))?,
            EndpointAdmission::Retiring
        ))?;
        let reject = Cell::new(false);
        let mut sender = Sender::new(
            remote.peer(),
            local.peer(),
            owner.sockets[0].profile().sender_policy(),
            100,
        )?;
        let packet = sender.initial(&remote, &[0, 5, 0, 0, 0x44], 10, 100, &mut Random(&reject))?;
        let address = owner.sockets[0].local_address();
        destination.send_to(packet.bytes(), address).await?;
        let receipt = owner.sockets[0].receive().await?;
        check(matches!(
            owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| Ok(1))?,
            Some(Activity::Discarded(Error::NotReady))
        ))?;
        check(journal.latest(remote.peer())?.is_none() && owner.peers() == 0)?;
        check(owner.endpoints() == 1)?;
        owner.restoring = true;
        check(matches!(
            owner.maintenance(Some(100))?,
            Some(Activity::Retired)
        ))?;
        check(
            owner.restore_fence == owner.next_effect && owner.restore_fence > owner.written_effect,
        )?;
        drain(&mut owner).await?;
        owner.restoring = false;
        // The discarded packet did not consume its authenticated replay stamp.
        destination.send_to(packet.bytes(), address).await?;
        let receipt = owner.sockets[0].receive().await?;
        check(matches!(
            owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| Ok(1))?,
            Some(Activity::Incoming { boxed: false, .. })
        ))?;
        check(journal.latest(remote.peer())? == Some(10))?;
        check(
            owner.endpoints() == 1
                && owner.endpoints[index]
                    .as_ref()
                    .is_some_and(|e| e.kx != old && !e.retiring),
        )?;
        owner.close();
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn identity_cut_cancels_original_packet_and_reuses_socket_backing_with_fresh_queue_ids()
-> Test {
    tokio::time::timeout(Duration::from_secs(5), async {
        let scratch = Scratch::new()?;
        let namespace = crate::replay::Namespace::open(&scratch.0)?;
        let a = Identity::from_seed([3; 32]);
        let b = Identity::from_seed([4; 32]);
        let remote = Identity::from_seed([5; 32]);
        let destination = UdpSocket::bind("127.0.0.1:0").await?;
        let target = destination.local_addr()?;
        let (mut owner, mut service) = owner(&a)?;
        let address = owner.sockets[0].local_address();
        let backing = owner.scratch.as_ptr();
        let mut journal = namespace.journal(a.peer(), 2)?;
        drain(&mut owner).await?;
        let _register = read_frame(&mut service).await?;
        let EndpointAdmission::New(plan) = owner.prepare_endpoint(remote.peer(), target, 100, &mut |_| Ok(1))? else { return Err("new endpoint required".into()); };
        let mut old = plan.endpoint.kx;
        owner.commit_endpoint(plan)?;
        drain(&mut owner).await?;
        check(setup(&read_frame(&mut service).await?)? == old)?;
        // Retain an actual original immutable packet before its UDP syscall.
        service.write_all(&send(remote.peer(), old, [9; 8], &[0, 5, 0, 0, 9])?).await?;
        let reject = Cell::new(false);
        while owner.completions.iter().all(Option::is_none) {
            poll_fn(|cx| owner.poll_step(cx, &a, &mut journal, 100, &mut Random(&reject), &mut |_| Ok(1))).await?;
        }
        let ticket = owner.advertise(7, b"udp-127.0.0.1:19773", 1, 12345)?;
        // Expose a real partial MQ prefix, independently of the pending packet.
        while owner.pending_mq.as_ref().is_none_or(|v| v.written_bytes == 0) {
            poll_fn(|cx| owner.poll_publications(cx)).await?;
        }
        for (index, next) in [&b, &a].into_iter().enumerate() {
            let cut = owner.retire_identity()?;
            check(cut.outgoing == 1 && cut.transport_was_attached && owner.identity_retired())?;
            let loss = owner.transport_loss().ok_or("actual retired source missing")?;
            if index == 0 {
                check(loss.retired.iter().any(|v| matches!(v, Retired::NativePending { .. })))?;
                check(loss.retired.iter().any(|v| matches!(v, Retired::Mq(m) if m.written_bytes > 0 && m.written_bytes < m.total_bytes)))?;
                check(owner.publication(&ticket)? == PublicationState::Retired)?;
                check(matches!(owner.resume_identity(next, &journal), Err(Failure::Core(Error::Authentication))))?;
            }
            let mut tail = Vec::new();
            service.read_to_end(&mut tail).await?; // original physical MQ really closed
            let mut packet = [0; 2048];
            check(destination.try_recv(&mut packet).is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock))?;
            check(DatagramSocket::bind(address).is_err())?; // original default descriptor still held
            check(owner.scratch.as_ptr() == backing && owner.sockets[0].local_address() == address)?;
            check(journal.quiescent()?)?;
            drop(journal);
            journal = namespace.journal(next.peer(), 2)?;
            owner.resume_identity(next, &journal)?;
            let (fresh_service, connection) = UnixStream::pair()?;
            service = fresh_service;
            owner.reconnect(Connection::from_unix(connection))?;
            drain(&mut owner).await?;
            let _register = read_frame(&mut service).await?;
            while owner.restoring {
                poll_fn(|cx| owner.poll_step(cx, next, &mut journal, 100, &mut Random(&reject), &mut |_| Ok(1))).await?;
            }
            let EndpointAdmission::New(plan) = owner.prepare_endpoint(remote.peer(), target, 100, &mut |_| Ok(1))? else { return Err("fresh endpoint required".into()); };
            let fresh = plan.endpoint.kx;
            check(fresh > old)?;
            owner.commit_endpoint(plan)?;
            let sent = Cell::new(0);
            let scenario = async {
                check(setup(&read_frame(&mut service).await?)? == fresh)?;
                service.write_all(&send(remote.peer(), old, [7;8], &[0,4,0,0])?).await?;
                ack(&read_frame(&mut service).await?,remote.peer(),old,[7;8],false)?;
                let body = [0,5,0,0,0x41 + index as u8];
                service.write_all(&send(remote.peer(),fresh,[8;8],&body)?).await?;
                ack(&read_frame(&mut service).await?,remote.peer(),fresh,[8;8],true)?;
                let (size, source) = destination.recv_from(&mut packet).await?;
                check(source == address)?;
                let mut plain = [0;2048];
                let opened = handshake::open(&remote,&packet[..size],&mut plain)?;
                check(opened.sender() == next.peer() && opened.monotonic() == if index == 0 {1} else {2})?;
                check(gnunet_udp_communicator_core::wire::Body::decode(opened.body())?.message == Some(&body))?;
                Ok::<(),Box<dyn std::error::Error>>(())
            };
            tokio::select! { result = drive(&mut owner,next,&mut journal,&reject,&sent) => result?, result = scenario => result? }
            check(sent.get() == 1)?;
            // The retained RX allocation must remain a full receive slot too.
            let mut reverse = Sender::new(remote.peer(),next.peer(),owner.sockets[0].profile().sender_policy(),100)?;
            let packet = reverse.initial(&remote,&[0,5,0,0,0x61],100 + index as u64,100,&mut Random(&reject))?;
            destination.send_to(packet.bytes(),address).await?;
            let receipt = owner.sockets[0].receive().await?;
            check(receipt.len() == 1452)?;
            check(matches!(owner.incoming(0,next,&mut journal,receipt,100,&mut |_| Ok(1))?,Some(Activity::Incoming { boxed:false,.. })))?;
            old = fresh;
        }
        owner.close();
        check(owner.is_quiescent())?;
        Ok::<(),Box<dyn std::error::Error>>(())
    }).await?
}
