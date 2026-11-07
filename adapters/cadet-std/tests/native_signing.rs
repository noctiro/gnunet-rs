//! Actual Rust standard-profile PILS socket/signatures. Book/CORE transmission
//! receipts are deliberately modeled; this does not prove C peer interoperability.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible native signer model asserts exact source/book/job, real signature, original partial cancellation and no reissue"
)]
use gnunet_cadet::connection::{
    self, Authentication, Book, Frame, FrameSlot, NeighborSlot, OriginSlot, RouteSlot,
};
use gnunet_cadet_host::{
    signing::{Completion, Connecting, JobSlot, Limits, Step},
    time::Timebase,
};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_pils::{
    Action, HelloLimits, MasterKey, Profile, Service,
    client::{self as pc, Instance},
};
use gnunet_pils_host::client::{self as native, EndpointSource, Progress};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::cadet_peer::{PathPeers, PeerMessage};
use std::{error::Error as StdError, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn StdError + Send + Sync>;
struct Socket(PathBuf);
impl Socket {
    fn new() -> Result<(Self, UnixListener), Failure> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnrs-cadet-sign-{}-{nanos}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}
fn hello() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 32,
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Option<Vec<u8>>, Failure> {
    let mut header = [0; 4];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err("short PILS fixture frame".into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(Some(bytes))
}
fn modeled_write<'book>(
    book: &mut Book<'book, '_, '_, 4>,
    frame: Frame<'book>,
    now: MonoInstant,
) -> Result<(), Error> {
    // No native CORE is started by this provider model. These are explicit pure
    // boundary observations solely to free Book queue storage for the next step.
    let queued = book.next_frame().ok_or(Error::NotReady)?;
    if queued.frame != frame {
        return Err(Error::StaleGeneration);
    }
    let neighbor = queued.neighbor;
    let attempt = book.start(frame)?;
    book.exposed(attempt)?;
    book.settle(attempt, true, now)?;
    book.release_frame(frame)?;
    // Model the next actual local request-admission capacity observation too;
    // a full modeled write is not itself an automatic remote ACK or credit.
    book.neighbor_ready(neighbor, true)
}
#[test]
fn actual_signer_retains_capacity_result_and_drains_original_partial_cancel_on_one_mq()
-> Result<(), Failure> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(8), async {
        let (socket, listener) = Socket::new()?;
        let mut service = Service::<4096>::new(
            MasterKey::from_seed([17; 32]),
            Profile::Reference029,
            SystemClock.sample()?.now.as_micros(),
            hello(),
        )?;
        let local = *service.identity().public_key().as_bytes();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(service.announcement()).await?;
            // An unchanged, valid HELLO is still a newer actual observation on
            // the same MQ; the pure client's revision must not be guessed.
            stream.write_all(service.announcement()).await?;
            let mut requests = 0;
            while let Some(request) = frame(&mut stream).await? {
                let mut output = [0; 104];
                let action = service.receive(
                    &request,
                    &mut [],
                    SystemClock.sample()?.now.as_micros(),
                    &mut output,
                )?;
                let Action::Reply {
                    len: 104,
                    crypto_error: None,
                } = action
                else {
                    return Err("actual PILS sign response was not standard104 bytes".into());
                };
                requests += 1;
                if requests == 1 {
                    // The old admitted operation remains owned while another
                    // same-key announcement precedes its actual signature.
                    stream.write_all(service.announcement()).await?;
                }
                stream.write_all(&output).await?;
            }
            Ok::<_, Failure>(requests)
        });
        let remote = *EddsaPrivateKey::from_seed([1; 32]).public_key().as_bytes();
        let mut instance = Instance::new();
        let mut connecting = Connecting::<4>::new(
            &mut instance,
            EndpointSource::unix(socket.0.clone()),
            local,
            Profile::Reference029,
            native::Limits {
                pending_operations: 4,
                io_slice_bytes: 1,
                ..native::Limits::default()
            },
            hello(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(6);
        let first_identity = loop {
            match connecting.drive(Some(deadline)).await? {
                Progress::Inbound(pc::Inbound::Identity { identity, .. }) => break identity,
                Progress::WaitDeadline => return Err("actual signer startup timeout".into()),
                _ => {}
            }
        };
        let timebase = Timebase::new(connecting.clock())?;
        let now = timebase.sample()?.monotonic;
        let mut book_instance = connection::Instance::new();
        let mut neighbors = [NeighborSlot::new(); 1];
        let mut routes = [RouteSlot::<4>::new(); 4];
        let mut origins = [OriginSlot::new(); 1];
        let mut bytes = [0; 512];
        let mut frames = [FrameSlot::new(&mut bytes)];
        let mut book = Book::new(
            &mut book_instance,
            local,
            &mut neighbors,
            &mut routes,
            &mut origins,
            &mut frames,
            now,
            connection::Limits::default(),
        )?;
        let neighbor = book.neighbor_up(remote)?;
        book.neighbor_ready(neighbor, true)?;
        let path = [local, remote];
        // Occupy the only Book output slot before an actual signature arrives.
        book.open(
            PathPeers::new(&path),
            [20; 32],
            Authentication::Unsigned,
            now,
        )?;
        let blocker = book.next_frame().ok_or(Error::NotReady)?.frame;
        let request = book
            .open(
                PathPeers::new(&path),
                [21; 32],
                Authentication::Monotime(100),
                now,
            )?
            .sign
            .ok_or(Error::NotReady)?;
        let mut jobs = [const { JobSlot::new() }; 1];
        // Equal source values do not bind an unrelated canonical clock to this
        // actual verified MQ. Refusal retains the same startup owner and rows.
        let other = Timebase::new(Arc::new(SystemClock))?;
        let connecting = match connecting.bind(&book, &mut jobs, Limits::default(), other) {
            Err(rejected) => {
                assert_eq!(rejected.reason, Error::StaleGeneration);
                rejected.value
            }
            Ok(_) => return Err("signer accepted an unrelated clock source".into()),
        };
        let mut signer = connecting
            .bind(&book, &mut jobs, Limits::default(), timebase.clone())
            .map_err(|r| r.reason)?;
        assert!(signer.timebase().same_epoch(&timebase));
        let expires = MonoInstant(now.0.checked_add(5_000_000).ok_or(Error::Overflow)?);
        let refreshed = loop {
            match signer.drive(Some(deadline)).await? {
                Step::Native(Progress::Inbound(pc::Inbound::Identity { identity, .. })) => {
                    break identity;
                }
                Step::Native(Progress::WaitDeadline) => {
                    return Err("same-MQ HELLO refresh timeout".into());
                }
                Step::IdentityChanged { .. } | Step::Lost { .. } | Step::Closed(_) => {
                    return Err("same-key HELLO replaced original source".into());
                }
                _ => {}
            }
        };
        assert_eq!(refreshed.epoch(), first_identity.epoch());
        assert_eq!(refreshed.peer(), first_identity.peer());
        assert!(refreshed.revision() > first_identity.revision());
        assert_eq!(signer.report().submitted, 0);
        let job = signer.submit(&book, request, expires)?;
        assert_eq!(job.expires(), expires);
        assert_eq!(
            job.hard_stop(),
            MonoInstant(
                expires
                    .0
                    .checked_add(Limits::default().retirement_grace_micros)
                    .ok_or(Error::Overflow)?
            )
        );
        assert_eq!(signer.job_for(request), Some(job));
        assert!(matches!(
            signer.submit(&book, request, expires),
            Err(gnunet_cadet_host::Error::Protocol(Error::Conflict))
        ));
        let mut refreshed_during_job = false;
        loop {
            match signer.drive(Some(deadline)).await? {
                Step::Ready { job: ready } if ready == job => break,
                Step::Native(Progress::Inbound(pc::Inbound::Identity { identity, .. })) => {
                    assert_eq!(identity.epoch(), first_identity.epoch());
                    assert_eq!(identity.peer(), first_identity.peer());
                    assert!(identity.revision() > refreshed.revision());
                    assert_eq!(signer.job_for(request), Some(job));
                    refreshed_during_job = true;
                }
                Step::Native(Progress::WaitDeadline) => {
                    return Err("actual purpose38 signature timeout".into());
                }
                Step::Lost { .. } | Step::Closed(_) => {
                    return Err("PILS lost before actual signature".into());
                }
                _ => {}
            }
        }
        assert!(refreshed_during_job);
        assert_eq!(
            signer.finish(&mut book, job)?,
            Completion::Blocked(Error::Capacity)
        );
        assert_eq!(signer.report().submitted, 1);
        assert_eq!(signer.report().received, 1);
        modeled_write(&mut book, blocker, signer.timebase().sample()?.monotonic)?;
        let Completion::Signed { frame: signed } = signer.finish(&mut book, job)? else {
            return Err("retained actual signature was not accepted".into());
        };
        assert_eq!(signer.job_for(request), None);
        let PeerMessage::ConnectionCreate {
            monotime: 100,
            has_monotime_bytes,
            ..
        } = PeerMessage::decode(book.frame_bytes(signed)?)?
        else {
            return Err("accepted signature did not queue original CREATE".into());
        };
        assert!(matches!(has_monotime_bytes, [1, 0, 0, 0] | [0, 0, 0, 1]));
        assert!(matches!(
            signer.finish(&mut book, job),
            Err(gnunet_cadet_host::Error::Protocol(Error::StaleGeneration))
        ));
        modeled_write(&mut book, signed, signer.timebase().sample()?.monotonic)?;
        book.neighbor_ready(neighbor, true)?;
        let now = signer.timebase().sample()?.monotonic;
        let canceled = book
            .open(
                PathPeers::new(&path),
                [22; 32],
                Authentication::Monotime(101),
                now,
            )?
            .sign
            .ok_or(Error::NotReady)?;
        let original = signer.submit(&book, canceled, expires)?;
        // Observe the first actual request byte before cancellation. Native SDK
        // must finish that exact immutable suffix rather than interleave a new op.
        loop {
            match signer.drive(Some(deadline)).await? {
                Step::Native(Progress::Activity {
                    written_bytes: 1, ..
                }) => break,
                Step::Native(Progress::WaitDeadline) => {
                    return Err("original sign prefix not exposed".into());
                }
                _ => {}
            }
        }
        assert!(!signer.retire(original)?);
        loop {
            let step = signer.drive(Some(deadline)).await?;
            if matches!(step, Step::Native(Progress::WaitDeadline)) {
                return Err("original canceled sign suffix failed to drain".into());
            }
            if signer.retire(original)? {
                break;
            }
        }
        assert_eq!(signer.job_for(canceled), None);
        // Tombstone still rejects that same live Signing request after physical
        // retirement, then the exact Book route closure allows finite row reuse.
        assert!(matches!(
            signer.submit(&book, canceled, expires),
            Err(gnunet_cadet_host::Error::Protocol(Error::Conflict))
        ));
        book.close_route(canceled.route())?;
        let now = signer.timebase().sample()?.monotonic;
        let next_request = book
            .open(
                PathPeers::new(&path),
                [23; 32],
                Authentication::Monotime(102),
                now,
            )?
            .sign
            .ok_or(Error::NotReady)?;
        let next = signer.submit(&book, next_request, expires)?;
        assert_ne!(next.operation(), original.operation());
        loop {
            match signer.drive(Some(deadline)).await? {
                Step::Ready { job: ready } if ready == next => break,
                Step::Ready { .. } => {
                    return Err("late canceled result completed another job".into());
                }
                Step::Native(Progress::WaitDeadline) => {
                    return Err("next actual signature timeout".into());
                }
                _ => {}
            }
        }
        assert!(matches!(
            signer.finish(&mut book, next)?,
            Completion::Signed { .. }
        ));
        assert_eq!(signer.report().submitted, 3);
        assert_eq!(signer.report().received, 2);
        assert_eq!(signer.report().applied, 2);
        assert_eq!(signer.report().retired, 1);
        let _retired = signer.close();
        assert!(matches!(
            signer.drive(Some(deadline)).await?,
            Step::Closed(Error::Closed)
        ));
        assert_eq!(server.await??, 3);
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
