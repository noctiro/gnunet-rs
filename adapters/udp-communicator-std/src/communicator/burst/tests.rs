//! Original IPC, private loopback probes and encrypted traffic; no NAT or C claim.
use super::*;
use crate::communicator::tests::{
    Scratch, Test, ack, check, create, drive_observed, frame, owner, read_frame, send, setup,
};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, SystemClock};
use gnunet_wire::official::communicator::Request;
use std::{
    cell::Cell,
    future::poll_fn,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
};

#[derive(Default)]
struct Clock {
    reads: AtomicUsize,
    delay_ms: u64,
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Error> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.delay_ms != 0 {
            std::thread::sleep(Duration::from_millis(self.delay_ms));
        }
        SystemClock.sample()
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        SystemClock.subscribe()
    }
}
struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Entropy)
    }
}
#[test]
fn report_consumption_keeps_earlier_retirements_ahead_of_new_work() {
    // Metadata FIFO policy only; these records assert no native execution.
    let instance = Instance::new();
    let report = |serial| Report {
        serial,
        peer: [0; 32],
        rtt_us: 0,
        outcome: Outcome::NotStarted(Error::Cancelled),
        ignored_scan_datagrams: 0,
    };
    let mut port = Port {
        instance: &instance,
        clock: Arc::new(SystemClock),
        policy: Policy::default(),
        serial: 2,
        active: None,
        report: Some(report(1)),
        cancelled: Some(report(2)),
        fence: None,
        changed: false,
    };
    assert!(matches!(port.take_report(), Some(Report { serial: 1, .. })));
    assert!(matches!(port.report, Some(Report { serial: 2, .. })));
    assert!(port.cancelled.is_none());
    assert!(matches!(port.take_report(), Some(Report { serial: 2, .. })));
    assert!(port.take_report().is_none());
}
async fn register(owner: &mut Communicator<'_>, service: &mut TcpStream) -> Test {
    while !owner.registered {
        poll_fn(|cx| owner.poll_publications(cx)).await?;
    }
    check(matches!(
        Request::decode(&read_frame(service).await?)?,
        Request::Register {
            can_burst: true,
            ..
        }
    ))
}
async fn load(owner: &mut Communicator<'_>, service: &mut TcpStream, peer: PeerId) -> Test {
    let ip = b"127.0.0.1";
    let mut bytes = frame(1253, 45 + ip.len())?;
    bytes[4..36].copy_from_slice(&peer);
    bytes[36..44].copy_from_slice(&123_u64.to_be_bytes());
    bytes[44..44 + ip.len()].copy_from_slice(ip);
    service.write_all(&bytes).await?;
    while owner.io.frame().is_none() {
        poll_fn(|cx| owner.io.poll_read(cx)).await?;
    }
    check(
        matches!(Event::decode(owner.io.frame().ok_or(Error::Stale)?)?, Event::Burst { peer: original, .. } if original == peer),
    )
}
fn command(
    owner: &mut Communicator<'_>,
    local: &Identity,
    journal: &mut Journal,
) -> Result<Option<Activity>, super::super::Failure> {
    owner.command(local, journal, 100, &mut NoEntropy, &mut |_| Ok(1))
}
fn policy(lifetime: Duration) -> Policy {
    Policy {
        lifetime,
        scan: native::Limits {
            sockets: 1,
            io_budget: 1,
            send_interval: Duration::from_millis(1),
            socket_lifetime: Duration::from_secs(1),
        },
        ..Policy::default()
    }
}
async fn guard(owner: &mut Communicator<'_>) -> Test {
    poll_fn(|cx| {
        if let Some(error) = owner.poll_native_guard(cx) {
            return Poll::Ready(Err(Box::new(error) as Box<dyn std::error::Error>));
        }
        Poll::Ready(Ok(()))
    })
    .await
}
async fn healthy(
    owner: &mut Communicator<'_>,
    service: &mut TcpStream,
    local: &Identity,
    journal: &mut Journal,
) -> Test {
    let remote = Identity::from_seed([7; 32]);
    let receiver = UdpSocket::bind("127.0.0.1:0").await?;
    let reject_entropy = Cell::new(false);
    let driving = drive_observed(owner, local, journal, &reject_entropy, |_| Ok(()));
    let scenario = async {
        service
            .write_all(&create(remote.peer(), receiver.local_addr()?)?)
            .await?;
        // A failed scan must not have inserted a 1254 before this real queue.
        let queue = setup(&read_frame(service).await?)?;
        check(matches!(
            Request::decode(&read_frame(service).await?)?,
            Request::Created(_, true)
        ))?;
        let payload = [0, 5, 0, 0, 0x37];
        service
            .write_all(&send(remote.peer(), queue, [5; 8], &payload)?)
            .await?;
        ack(
            &read_frame(service).await?,
            remote.peer(),
            queue,
            [5; 8],
            true,
        )?;
        let mut packet = [0; 2048];
        let n = receiver.recv(&mut packet).await?;
        let mut scratch = [0; 2048];
        let opened = handshake::open(&remote, &packet[..n], &mut scratch)?;
        check(
            opened.sender() == local.peer()
                && gnunet_udp_communicator_core::wire::Body::decode(opened.body())?.message
                    == Some(&payload),
        )
    };
    tokio::select! { result = driving => result, result = scenario => result }
}

#[tokio::test(flavor = "current_thread")]
async fn supersession_running_and_report_blocked_expiry_keep_the_original_socket_and_mq() -> Test {
    tokio::time::timeout(Duration::from_secs(5), async {
        let directory = Scratch::new()?;
        let local = Identity::from_seed([3; 32]);
        let instance = Instance::new();
        let clock = Arc::new(Clock::default());
        let (mut owner, mut service) = owner(&local).await?;
        owner.enable_burst(&instance, clock.clone(), policy(Duration::from_millis(100)))?;
        let mut journal = Journal::open(&directory.0, local.peer(), 2)?;
        register(&mut owner, &mut service).await?;
        let original_socket = owner.sockets[0].local_address();
        let generation = owner.transport_generation();
        load(
            &mut owner,
            &mut service,
            Identity::from_seed([5; 32]).peer(),
        )
        .await?;
        check(matches!(
            command(&mut owner, &local, &mut journal)?,
            Some(Activity::Burst)
        ))?;
        // A fresh real command replaces just the old probe. Report backpressure
        // keeps the next original frame and bound, without starting its utility.
        load(
            &mut owner,
            &mut service,
            Identity::from_seed([6; 32]).peer(),
        )
        .await?;
        check(command(&mut owner, &local, &mut journal)?.is_none())?;
        let old = owner.take_burst_report().ok_or(Error::NotReady)?;
        check(
            old.peer == Identity::from_seed([5; 32]).peer()
                && matches!(
                    &old.outcome,
                    Outcome::Stopped {
                        cause: native::Cause::Cancelled,
                        interrupted: Some(Error::Cancelled),
                        ..
                    }
                )
                && old.completion().is_none(),
        )?;
        check(matches!(
            command(&mut owner, &local, &mut journal)?,
            Some(Activity::Burst)
        ))?;
        let hard = owner
            .burst
            .as_ref()
            .and_then(|port| port.active.as_ref())
            .ok_or(Error::Stale)?
            .command
            .hard;
        tokio::time::sleep_until(hard.into()).await;
        guard(&mut owner).await?;
        load(
            &mut owner,
            &mut service,
            Identity::from_seed([9; 32]).peer(),
        )
        .await?;
        let reads = clock.reads.load(Ordering::Relaxed);
        check(command(&mut owner, &local, &mut journal)?.is_none())?;
        let hard = owner
            .burst
            .as_ref()
            .and_then(|port| port.active.as_ref())
            .ok_or(Error::Stale)?
            .command
            .hard;
        tokio::time::sleep_until(hard.into()).await;
        guard(&mut owner).await?;
        check(
            command(&mut owner, &local, &mut journal)?.is_none()
                && clock.reads.load(Ordering::Relaxed) == reads,
        )?;
        let active = owner
            .burst
            .as_ref()
            .and_then(|port| port.active.as_ref())
            .ok_or(Error::Stale)?;
        check(
            active.command.hard == hard
                && matches!(
                    &active.phase,
                    Phase::Retired(Retired {
                        outcome: Outcome::NotStarted(Error::Deadline),
                        input: Some(_)
                    })
                )
                && owner.io.frame().is_some(),
        )?;
        // A retired or unstarted probe cannot pin the original shared RX loan
        // while the SDK retains a prior report. Ordinary dispatch consumes this
        // unsolicited nonzero-port probe without granting a burst completion.
        let unsolicited = UdpSocket::bind("127.0.0.1:0").await?;
        let probe = native::wire::BurstMessage {
            peer: Identity::from_seed([5; 32]).peer(),
            local_port: 12345,
        }
        .to_bytes(local_order());
        unsolicited.send_to(&probe, original_socket).await?;
        let receipt = owner.sockets[0].receive().await?;
        check(matches!(
            owner.incoming(0, &local, &mut journal, receipt, 100, &mut |_| Ok(1))?,
            Some(Activity::Discarded(Error::InvalidInput))
        ))?;
        check(owner.io.frame().is_some())?;
        let running = owner.take_burst_report().ok_or(Error::NotReady)?;
        check(
            matches!(
                &running.outcome,
                Outcome::Stopped {
                    cause: native::Cause::Deadline(native::DeadlineKind::Hard),
                    ..
                }
            ) && !running.candidate_installed()
                && running.completion().is_none(),
        )?;
        guard(&mut owner).await?;
        let waiting = owner.take_burst_report().ok_or(Error::NotReady)?;
        check(
            waiting.peer == Identity::from_seed([9; 32]).peer()
                && matches!(&waiting.outcome, Outcome::NotStarted(Error::Deadline))
                && owner.io.frame().is_none(),
        )?;
        healthy(&mut owner, &mut service, &local, &mut journal).await?;
        check(
            owner.transport_generation() == generation
                && owner.transport_attached()
                && owner.sockets[0].local_address() == original_socket,
        )?;
        owner.close();
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn slow_preparation_cannot_renew_the_original_native_bound() -> Test {
    let directory = Scratch::new()?;
    let local = Identity::from_seed([3; 32]);
    let instance = Instance::new();
    let clock = Arc::new(Clock {
        delay_ms: 30,
        ..Clock::default()
    });
    let (mut owner, mut service) = owner(&local).await?;
    owner.enable_burst(&instance, clock.clone(), policy(Duration::from_millis(10)))?;
    let mut journal = Journal::open(&directory.0, local.peer(), 2)?;
    register(&mut owner, &mut service).await?;
    load(
        &mut owner,
        &mut service,
        Identity::from_seed([5; 32]).peer(),
    )
    .await?;
    check(matches!(
        command(&mut owner, &local, &mut journal)?,
        Some(Activity::Burst)
    ))?;
    let report = owner.take_burst_report().ok_or(Error::NotReady)?;
    check(
        matches!(&report.outcome, Outcome::NotStarted(Error::Deadline))
            && report.scan().datagrams_written == 0
            && clock.reads.load(Ordering::Relaxed) == 1
            && owner.io.frame().is_none()
            && owner.transport_attached()
            && !owner.is_closed(),
    )?;
    owner.close();
    Ok(())
}

#[derive(Clone, Copy)]
enum Decision {
    Install,
    Expire,
    Refuse,
}
async fn candidate(scan: bool, decision: Decision) -> Test {
    let directory = Scratch::new()?;
    let local = Identity::from_seed([3; 32]);
    let instance = Instance::new();
    let (mut owner, mut service) = owner(&local).await?;
    owner.enable_burst(
        &instance,
        Arc::new(SystemClock),
        policy(Duration::from_millis(200)),
    )?;
    let mut journal = Journal::open(&directory.0, local.peer(), 2)?;
    register(&mut owner, &mut service).await?;
    load(
        &mut owner,
        &mut service,
        Identity::from_seed([5; 32]).peer(),
    )
    .await?;
    command(&mut owner, &local, &mut journal)?;
    // Real utility packets remain on loopback. With a loopback remote, a scan
    // socket can observe its own public probe; this proves no remote identity.
    poll_fn(|cx| {
        let utility = owner
            .burst
            .as_mut()
            .and_then(|port| port.active.as_mut())
            .and_then(|active| match &mut active.phase {
                Phase::Running(owner) => Some(owner),
                _ => None,
            })
            .ok_or(Error::Stale)?;
        let step = utility.poll_step(cx, |_| {});
        if (scan && matches!(step, Poll::Ready(native::Step::Selected)))
            || (!scan && utility.report().datagrams_written > 0)
        {
            return Poll::Ready(Ok::<_, Box<dyn std::error::Error>>(()));
        }
        if matches!(step, Poll::Ready(native::Step::Stopped)) {
            return Poll::Ready(Err(
                format!("loopback probe stopped: {:?}", utility.end()).into()
            ));
        }
        if step.is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await?;
    if !scan {
        let receipt = poll_fn(|cx| owner.sockets[0].poll_receive(cx)).await?;
        check(matches!(owner.burst_probe(0, receipt)?, Probe::Selected))?;
    }
    let selected = owner
        .burst
        .as_ref()
        .and_then(|port| port.active.as_ref())
        .and_then(|active| match &active.phase {
            Phase::Running(owner) => Some(owner),
            _ => None,
        })
        .and_then(Burst::selection)
        .ok_or(Error::NotReady)?;
    check(selected.id.is_default() != scan)?;
    let selected_address = selected.socket.socket().local_addr()?;
    let next_queue = owner.next_queue;
    let classified = Cell::new(false);
    poll_fn(|cx| {
        Poll::Ready(owner.burst_step(cx, 100, &mut |_| {
            classified.set(true);
            match decision {
                Decision::Install => Ok(1),
                Decision::Expire => {
                    std::thread::sleep(Duration::from_millis(250));
                    Ok(1)
                }
                Decision::Refuse => Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "original classifier observation",
                )),
            }
        }))
    })
    .await?;
    let report = owner.take_burst_report().ok_or(Error::NotReady)?;
    check(classified.get() && owner.transport_attached() && !owner.sockets[0].is_closed())?;
    if matches!(decision, Decision::Install) {
        let completion = report.completion().ok_or(Error::NotReady)?;
        check(
            report.candidate_installed()
                && owner.endpoints() == 1
                && owner.publication(completion)? == PublicationState::Pending,
        )?;
        while owner.publication(completion)? == PublicationState::Pending {
            poll_fn(|cx| owner.poll_publications(cx)).await?;
        }
        check(matches!(
            Request::decode(&read_frame(&mut service).await?)?,
            Request::QueueSetup(_, _)
        ))?;
        check(matches!(
            Request::decode(&read_frame(&mut service).await?)?,
            Request::BurstFinished
        ))?;
        check(owner.publication(completion)? == PublicationState::Written)?;
        if scan {
            check(
                owner.sockets.len() == owner.defaults + 1
                    && !owner.sockets[owner.defaults].is_closed(),
            )?;
        }
    } else {
        check(match (&decision, &report.outcome) {
            (
                Decision::Expire,
                Outcome::Rejected {
                    reason: Refusal::Protocol(Error::Deadline),
                    ..
                },
            ) => true,
            (
                Decision::Refuse,
                Outcome::Rejected {
                    reason: Refusal::Classification(error),
                    ..
                },
            ) => error.kind() == io::ErrorKind::AddrNotAvailable,
            _ => false,
        })?;
        check(
            !report.candidate_installed()
                && report.completion().is_none()
                && owner.endpoints() == 0
                && owner.next_queue == next_queue
                && owner.effects.is_empty(),
        )?;
        if scan {
            check(owner.sockets.len() == owner.defaults)?;
            let replacement = UdpSocket::bind(selected_address).await?;
            drop(replacement);
        }
    }
    owner.close();
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn late_default_selection_preserves_the_original_socket_without_a_queue() -> Test {
    tokio::time::timeout(Duration::from_secs(5), candidate(false, Decision::Expire)).await?
}
#[tokio::test(flavor = "current_thread")]
async fn late_scan_selection_retires_its_adopted_socket_without_a_queue() -> Test {
    tokio::time::timeout(Duration::from_secs(5), candidate(true, Decision::Expire)).await?
}

#[tokio::test(flavor = "current_thread")]
async fn default_selection_reports_only_its_actual_completion_write() -> Test {
    tokio::time::timeout(Duration::from_secs(5), candidate(false, Decision::Install)).await?
}
#[tokio::test(flavor = "current_thread")]
async fn scan_selection_promotes_the_original_owner_with_its_queue() -> Test {
    tokio::time::timeout(Duration::from_secs(5), candidate(true, Decision::Install)).await?
}
#[tokio::test(flavor = "current_thread")]
async fn classification_refusal_drops_only_the_staged_scan_socket() -> Test {
    tokio::time::timeout(Duration::from_secs(5), candidate(true, Decision::Refuse)).await?
}
