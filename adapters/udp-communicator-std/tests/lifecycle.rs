//! Real original MQ/socket retirement and persistence-fence admission boundaries.
#![cfg(feature = "transport")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite OS ownership witnesses assert original EOF, exact refusal and namespace/fence boundaries."
)]

use gnunet_crypto::Entropy;
use gnunet_service_runtime::connection::Connection;
use gnunet_types::Error;
use gnunet_udp_communicator_core::Identity;
use gnunet_udp_communicator_host::{
    driver::{Capacity, Configuration, Driver, DriverError},
    replay::{Journal, JournalError, Outcome, Stage},
    socket::DatagramSocket,
};
use std::{
    future::poll_fn,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::UnixStream};
type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "udp-lifecycle-{}-{}",
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
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(bytes).map_err(|_| Error::Entropy)
    }
}
fn driver(local: &Identity) -> Result<(Driver, UnixStream), Box<dyn std::error::Error>> {
    let socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
    let target = socket.local_address();
    let (service, communicator) = UnixStream::pair()?;
    let configuration = Configuration {
        local: local.peer(),
        peer: Identity::from_seed([5; 32]).peer(),
        target,
        network: 1,
        capacity: Capacity {
            io_slice: 1,
            ..Capacity::default()
        },
        transmit: socket.profile().sender_policy(),
    };
    Ok((
        Driver::new(
            Connection::from_unix(communicator),
            socket,
            configuration,
            100,
        )?,
        service,
    ))
}
async fn original_closed(driver: &Driver, mut service: UnixStream) -> Test {
    assert!(driver.is_quiescent());
    let mut wire = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), service.read_to_end(&mut wire)).await??;
    assert!(wire.is_empty());
    // The same actual endpoint can be rebound only after the original native
    // owner has retired; this is stronger than a logical closed flag alone.
    let rebound = DatagramSocket::bind(driver.local_address())?;
    assert_eq!(rebound.local_address(), driver.local_address());
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn foreign_identity_retires_original_mq_and_native_socket_before_old_output() -> Test {
    let scratch = Scratch::new()?;
    let local = Identity::from_seed([3; 32]);
    let foreign = Identity::from_seed([7; 32]);
    let (mut driver, service) = driver(&local)?;
    let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
    let result = poll_fn(|cx| driver.poll_step(cx, &foreign, &mut journal, 100, &mut Random)).await;
    assert!(matches!(
        result,
        Err(DriverError::Core(Error::Authentication))
    ));
    assert_eq!(journal.commits(), 0);
    original_closed(&driver, service).await
}
#[tokio::test(flavor = "current_thread")]
async fn foreign_local_replay_namespace_retires_original_io_before_old_output() -> Test {
    let scratch = Scratch::new()?;
    let local = Identity::from_seed([3; 32]);
    let (mut driver, service) = driver(&local)?;
    let mut journal = Journal::open(&scratch.0, Identity::from_seed([7; 32]).peer(), 2)?;
    let result = poll_fn(|cx| driver.poll_step(cx, &local, &mut journal, 100, &mut Random)).await;
    assert!(matches!(
        result,
        Err(DriverError::Core(Error::Authentication))
    ));
    assert_eq!(journal.commits(), 0);
    original_closed(&driver, service).await
}
#[tokio::test(flavor = "current_thread")]
async fn replaced_real_writer_fence_stops_all_io_until_original_inode_restored() -> Test {
    let scratch = Scratch::new()?;
    let local = Identity::from_seed([3; 32]);
    let (mut driver, service) = driver(&local)?;
    let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
    let mut service = service.into_std()?;
    let lock = scratch.0.join(".gnunet-udp-replay-owner.lock");
    let original = scratch.0.join("original-fence");
    std::fs::rename(&lock, &original)?;
    std::fs::write(&lock, [])?;
    for _ in 0..2 {
        let result =
            poll_fn(|cx| driver.poll_step(cx, &local, &mut journal, 100, &mut Random)).await;
        assert!(matches!(
            result,
            Err(DriverError::History(JournalError::Native(ref failure)))
                if failure.stage == Stage::Fence && failure.outcome == Outcome::Unknown
        ));
        assert!(matches!(
            std::io::Read::read(&mut service, &mut [0; 64]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert_eq!(journal.commits(), 0);
    }
    std::fs::remove_file(&lock)?;
    std::fs::rename(&original, &lock)?;
    assert!(journal.quiescent()?);
    // Recovery validates the actual original fence, then the same original
    // session can make progress. No token or replacement journal authorizes it.
    poll_fn(
        |cx| match driver.poll_step(cx, &local, &mut journal, 100, &mut Random) {
            Poll::Ready(Ok(gnunet_udp_communicator_host::driver::Activity::Io)) => {
                Poll::Ready(Ok::<_, DriverError>(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        },
    )
    .await?;
    let mut byte = [0; 1];
    assert_eq!(std::io::Read::read(&mut service, &mut byte)?, 1);
    assert_eq!(byte, [0]); // first original registration header byte
    driver.close();
    assert!(driver.is_quiescent());
    Ok(())
}
#[cfg(feature = "pils-client")]
#[tokio::test(flavor = "current_thread")]
async fn actual_pils_mq_eof_revokes_bound_driver_and_discards_cached_old_output() -> Test {
    use gnunet_pils::{HelloLimits, MasterKey, Profile, Service, client::Instance};
    use gnunet_pils_host::client::{Client, EndpointSource, Limits, Progress};
    use gnunet_udp_communicator_host::{driver::Time, identity::IdentityEpoch};
    use gnunet_wire::official::AbsoluteTime;
    use tokio::{io::AsyncWriteExt, net::UnixListener, time::Instant};
    let scratch = Scratch::new()?;
    let listener = UnixListener::bind(scratch.0.join("pils.sock"))?;
    let endpoint = EndpointSource::unix(scratch.0.join("pils.sock"));
    let clock = endpoint.clock();
    let now = clock.sample()?.now.as_micros();
    let limits = HelloLimits {
        maximum_input_bytes: 4096,
        maximum_address_bytes: 1024,
        maximum_addresses: 16,
    };
    let source = Service::<2048>::new(
        MasterKey::from_seed([3; 32]),
        Profile::Reference029,
        now,
        limits,
    )?;
    let mut instance = Instance::new();
    let mut pils = Client::<4>::new(
        &mut instance,
        endpoint,
        Profile::Reference029,
        Limits {
            pending_operations: 4,
            ..Limits::default()
        },
        limits,
    )?;
    pils.enable_local_key(MasterKey::from_seed([3; 32]))?;
    let deadline = Some(Instant::now() + Duration::from_secs(2));
    assert!(matches!(
        pils.drive(deadline).await?,
        Progress::Connected(_)
    ));
    let (mut physical_pils, _) = listener.accept().await?;
    physical_pils.write_all(source.announcement()).await?;
    while pils.identity().is_none() {
        match pils.drive(deadline).await? {
            Progress::Activity { .. } | Progress::Inbound(_) => {}
            _ => return Err("actual PILS announcement failed".into()),
        }
    }
    let mut binding = IdentityEpoch::from_native(&pils, AbsoluteTime::from_micros(now))?;
    let local = binding.current_native(&pils, AbsoluteTime::from_micros(now))?;
    let (mut driver, service) = driver(local)?;
    let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
    drop(physical_pils);
    loop {
        match pils.drive(deadline).await? {
            Progress::Lost { .. } => break,
            Progress::Activity { .. } => {}
            _ => return Err("actual PILS EOF failed to retire original epoch".into()),
        }
    }
    let sample = clock.sample()?.now.as_micros();
    let result = poll_fn(|cx| {
        driver.poll_bound(
            cx,
            &binding,
            &pils,
            &mut journal,
            Time {
                now: sample,
                utc: AbsoluteTime::from_micros(sample),
            },
            &mut Random,
        )
    })
    .await;
    assert!(matches!(result, Err(DriverError::Core(Error::Stale))));
    assert_eq!(journal.commits(), 0);
    original_closed(&driver, service).await?;
    binding.close();
    assert!(pils.close().iter().all(Option::is_none));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn finish_cancels_original_unsent_datagram_then_drains_failure_and_queue_eof() -> Test {
    use gnunet_udp_communicator_host::driver::Activity;
    use tokio::io::AsyncWriteExt;
    let scratch = Scratch::new()?;
    let local = Identity::from_seed([3; 32]);
    let peer = Identity::from_seed([5; 32]).peer();
    let remote = std::net::UdpSocket::bind("127.0.0.1:0")?;
    remote.set_nonblocking(true)?;
    let socket = DatagramSocket::bind("127.0.0.1:0".parse()?)?;
    let (mut service, communicator) = UnixStream::pair()?;
    let configuration = Configuration {
        local: local.peer(),
        peer,
        target: remote.local_addr()?,
        network: 1,
        capacity: Capacity {
            io_slice: 1,
            ..Capacity::default()
        },
        transmit: socket.profile().sender_policy(),
    };
    let mut driver = Driver::new(
        Connection::from_unix(communicator),
        socket,
        configuration,
        100,
    )?;
    let mut journal = Journal::open(&scratch.0, local.peer(), 2)?;
    let mid = [0x41; 8];
    let mut request = [0; 56];
    request[..2].copy_from_slice(&56u16.to_be_bytes());
    request[2..4].copy_from_slice(&1209u16.to_be_bytes());
    request[4..8].copy_from_slice(&1u32.to_be_bytes());
    request[8..16].copy_from_slice(&mid);
    request[16..48].copy_from_slice(&peer);
    request[48..].copy_from_slice(&[0, 8, 0, 0, 1, 2, 3, 4]);
    service.write_all(&request).await?;
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(
            |cx| match driver.poll_step(cx, &local, &mut journal, 100, &mut Random) {
                Poll::Ready(Ok(Activity::Command)) => Poll::Ready(Ok::<_, DriverError>(())),
                Poll::Ready(Ok(Activity::NativeSent { .. })) => {
                    Poll::Ready(Err(Error::InvalidInput.into()))
                }
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            },
        ),
    )
    .await??;
    assert_eq!(journal.commits(), 1); // original monotime reservation is durable
    driver.finish()?; // cancel before the original native send syscall is polled
    let mut service = service.into_std()?;
    let mut wire = Vec::new();
    let mut eof = false;
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| {
            let mut progress = false;
            if !driver.is_quiescent() {
                match driver.poll_step(cx, &local, &mut journal, 100, &mut Random) {
                    Poll::Ready(Ok(Activity::NativeSent { .. })) => {
                        return Poll::Ready(Err(Error::InvalidInput.into()));
                    }
                    Poll::Ready(Ok(_)) => progress = true,
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(Box::<dyn std::error::Error>::from(error)));
                    }
                    Poll::Pending => {}
                }
            }
            loop {
                let mut bytes = [0; 512];
                match std::io::Read::read(&mut service, &mut bytes) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => {
                        wire.extend_from_slice(&bytes[..n]);
                        progress = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Poll::Ready(Err(error.into())),
                }
            }
            if driver.is_quiescent() && eof {
                return Poll::Ready(Ok::<_, Box<dyn std::error::Error>>(()));
            }
            if progress {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }),
    )
    .await??;
    assert!(
        matches!(remote.recv_from(&mut [0; 2048]), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(journal.commits(), 1);
    let mut offset = 0;
    let mut callbacks = 0;
    let mut downs = 0;
    while offset < wire.len() {
        let n = usize::from(u16::from_be_bytes([wire[offset], wire[offset + 1]]));
        let frame = wire.get(offset..offset + n).ok_or(Error::Truncated)?;
        let kind = gnunet_wire::official::Frame::decode(frame)?
            .header()
            .message_type();
        if kind == gnunet_wire::official::message_type::TRANSPORT_SEND_MSG_ACK {
            callbacks += 1;
            assert_eq!(frame.len(), 52);
            assert_eq!(&frame[4..8], &(-1i32).to_be_bytes());
            assert_eq!(&frame[8..16], &mid);
            assert_eq!(&frame[16..20], &1u32.to_be_bytes());
            assert_eq!(&frame[20..], &peer);
            assert_eq!(downs, 0);
        }
        if kind == gnunet_wire::official::message_type::TRANSPORT_QUEUE_TEARDOWN {
            downs += 1;
            assert_eq!(callbacks, 1);
            assert_eq!(&frame[4..8], &1u32.to_be_bytes());
            assert_eq!(&frame[8..], &peer);
        }
        offset += n;
    }
    assert_eq!((callbacks, downs), (1, 1));
    assert!(eof && driver.is_quiescent());
    Ok(())
}
