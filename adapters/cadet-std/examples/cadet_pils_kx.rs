//! Component driver: actual standard C PILS DH plus pure CADET KX/AEAD.
//! Usage: cadet_pils_kx PILS_UNIXPATH
//! The two Book/CORE links are an explicit in-process authorization model.
//! This does not start C CADET or demonstrate encrypted cross-peer CORE IO.
use gnunet_cadet::{
    connection::{self, Authentication, Book, FrameSlot, Neighbor, NeighborSlot, RouteSlot},
    tunnel::{
        self, Context, Identity, Role, SkippedSlot, Storage, context,
        controller::{Controller, Event, Kind, Stores},
        identity_dh,
    },
};
use gnunet_cadet_host::{
    EndpointSource,
    identity_dh::{Connecting, ContextSlot, JobSlot, Port, Step},
    time::Timebase,
};
use gnunet_crypto::Entropy;
use gnunet_pils::{
    HelloLimits, Profile,
    client::{Inbound, Instance},
};
use gnunet_pils_host::client::{self as native, Client, LossCause, Progress};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::cadet_peer::{ChannelMessage, PathPeers, PeerMessage};
use std::{
    error::Error as StdError,
    fmt,
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;

type Failure = Box<dyn StdError + Send + Sync>;
const PLAIN: [u8; 4] = [0, 4, 3, 244];
const CAPACITY: usize = 512;

// The only seed this example creates is its own independent Rust counterpart.
// Every LocalKeys scalar and AEAD nonce also comes from fresh OS randomness.
struct OsEntropy(File);
impl OsEntropy {
    fn new() -> Result<Self, Failure> {
        Ok(Self(File::open("/dev/urandom")?))
    }
}
impl Entropy for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.0.read_exact(out).map_err(|_| Error::Entropy)
    }
}

#[derive(Debug)]
struct ActualLoss {
    epoch: u64,
    cause: LossCause,
    retained: usize,
    feeds: usize,
}
impl fmt::Display for ActualLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original PILS MQ lost: epoch={} cause={:?} retained={} feeds={}",
            self.epoch, self.cause, self.retained, self.feeds
        )
    }
}
impl StdError for ActualLoss {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.cause {
            LossCause::Io(error) => Some(error),
            LossCause::Protocol(error) | LossCause::Resource(error) => Some(error),
            LossCause::Setup(error) => Some(error),
            LossCause::Eof | LossCause::Requested => None,
        }
    }
}

fn require(ok: bool, reason: &'static str) -> Result<(), Failure> {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn within(deadline: Instant) -> Result<(), Failure> {
    require(
        Instant::now() < deadline,
        "component observation deadline elapsed",
    )
}
fn hello() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 32,
    }
}
fn native_limits() -> native::Limits {
    native::Limits {
        pending_operations: 2,
        io_slice_bytes: 31,
        ..native::Limits::default()
    }
}
fn native_progress(progress: Progress<'_, 2>) -> Result<(), Failure> {
    match progress {
        Progress::Connected(_)
        | Progress::Written(_)
        | Progress::Activity { .. }
        | Progress::Inbound(Inbound::Ignored | Inbound::Identity { .. }) => Ok(()),
        Progress::Lost {
            epoch,
            cause,
            report,
        } => Err(Box::new(ActualLoss {
            epoch: epoch.value(),
            cause,
            retained: report.retained(),
            feeds: report.feeds().count(),
        })),
        Progress::ConnectRetry { error, .. } => Err(error.into()),
        Progress::Unavailable(error) => Err(error.into()),
        Progress::WaitDeadline => {
            Err("PILS wait deadline elapsed; original operation still needs retirement".into())
        }
        Progress::Closed => Err("original PILS source closed".into()),
        Progress::Inbound(Inbound::Complete(_)) => {
            Err("unexpected direct result outside private DH provider".into())
        }
    }
}

async fn observe(
    path: PathBuf,
    clock: Arc<dyn RuntimeClock>,
    deadline: Instant,
) -> Result<[u8; 32], Failure> {
    let mut instance = Instance::new();
    let mut client = Client::<2>::new(
        &mut instance,
        EndpointSource::unix_with_clock(path, clock),
        Profile::Reference029,
        native_limits(),
        hello(),
    )?;
    let result = async {
        loop {
            within(deadline)?;
            match client.drive(Some(deadline)).await? {
                Progress::Inbound(Inbound::Identity { identity, .. }) => {
                    return Ok(*identity.peer().as_bytes());
                }
                progress => native_progress(progress)?,
            }
        }
    }
    .await;
    let retired = client.close();
    if result.is_ok() {
        require(
            retired.iter().all(Option::is_none),
            "public-only observer unexpectedly owned an operation",
        )?;
    }
    result
}

fn counterpart(
    local: [u8; 32],
    local_role: Role,
    entropy: &mut OsEntropy,
    deadline: Instant,
) -> Result<Identity, Failure> {
    for _ in 0..4096 {
        within(deadline)?;
        let mut seed = Zeroizing::new([0; 32]);
        entropy.fill(&mut *seed)?;
        let identity = Identity::from_seed(*seed);
        if match local_role {
            Role::Alice => local < identity.peer(),
            Role::Betty => local > identity.peer(),
        } {
            return Ok(identity);
        }
    }
    Err("fresh Rust counterpart search exhausted its explicit bound".into())
}

struct Crypto {
    a: [SkippedSlot; 4],
    b: [SkippedSlot; 4],
    c: [SkippedSlot; 4],
    d: [SkippedSlot; 4],
}
impl Crypto {
    fn new() -> Self {
        Self {
            a: [const { SkippedSlot::new() }; 4],
            b: [const { SkippedSlot::new() }; 4],
            c: [const { SkippedSlot::new() }; 4],
            d: [const { SkippedSlot::new() }; 4],
        }
    }
    fn stores(&mut self) -> Stores<'_> {
        Stores {
            first: Storage {
                skipped: &mut self.a,
                staging: &mut self.b,
            },
            second: Storage {
                skipped: &mut self.c,
                staging: &mut self.d,
            },
        }
    }
}

// This is deliberately a MODEL physical link. No call here claims an actual
// CORE byte, neighbor authentication, C tunnel packet, or peer application ACK.
fn model_frame(
    book: &mut Book<'_, '_, '_, 2>,
    now: MonoInstant,
    out: &mut [u8; CAPACITY],
) -> Result<usize, Failure> {
    let queued = book.next_frame().ok_or(Error::NotReady)?;
    let frame = queued.frame;
    let neighbor = queued.neighbor;
    let size = queued.bytes.len();
    out.get_mut(..size)
        .ok_or(Error::Capacity)?
        .copy_from_slice(queued.bytes);
    let attempt = book.start(frame)?;
    book.exposed(attempt)?;
    book.settle(attempt, true, now)?;
    book.release_frame(frame)?;
    // The modeled local request queue is available again; this is no wire READY.
    book.neighbor_ready(neighbor, true)?;
    Ok(size)
}

fn model_control<'id, 'route>(
    controller: &mut Controller<'id, '_, 'route>,
    book: &mut Book<'route, '_, '_, 2>,
    now: MonoInstant,
    entropy: &mut OsEntropy,
    output: &mut [u8; CAPACITY],
) -> Result<(usize, Kind), Failure> {
    let mut preview = [0; CAPACITY];
    let prepared = controller
        .prepare(controller.scope(), book, now, &mut preview, entropy)?
        .ok_or(Error::NotReady)?;
    let tag = prepared.attempt();
    let size = prepared.bytes().len();
    output[..size].copy_from_slice(prepared.bytes());
    let message = match PeerMessage::decode(prepared.bytes()) {
        Ok(message) => message,
        Err(reason) => {
            controller.reject_prepared(prepared)?;
            return Err(reason.into());
        }
    };
    let frame = match book.queue_payload(tag.route(), message, now) {
        Ok(frame) => frame,
        Err(reason) => {
            controller.reject_prepared(prepared)?;
            return Err(reason.into());
        }
    };
    let attempt = book.start(frame)?;
    if let Err(rejected) = controller.submit(prepared, book, attempt) {
        controller.reject_prepared(rejected.prepared)?;
        book.settle(attempt, false, now)?;
        book.release_frame(frame)?;
        return Err(rejected.reason.into());
    }
    book.exposed(attempt)?;
    let completion = book.settle(attempt, true, now)?;
    let outcome = controller.complete(tag, completion, now);
    let released = book.release_frame(frame);
    outcome?;
    released?;
    // Restore the modeled local admission capacity after the original write.
    book.neighbor_ready(completion.neighbor, true)?;
    Ok((size, tag.kind()))
}

fn accept_control<'id, 'route>(
    controller: &mut Controller<'id, '_, 'route>,
    book: &mut Book<'route, '_, '_, 2>,
    neighbor: Neighbor<'route>,
    wire: &[u8],
    now: MonoInstant,
    entropy: &mut OsEntropy,
) -> Result<Event<'id>, Failure> {
    let connection::Event::Endpoint(input) =
        book.receive(neighbor, PeerMessage::decode(wire)?, now)?
    else {
        return Err("modeled connection did not authorize exact endpoint control".into());
    };
    Ok(controller.control(controller.scope(), input, now, entropy)?)
}

async fn finish_dh<'id>(
    controller: &mut Controller<'id, '_, '_>,
    port: &mut Port<'id, '_, '_, 2>,
    deadline: Instant,
) -> Result<(), Failure> {
    let original = controller.pending_identity_dh().ok_or(Error::NotReady)?;
    let now = port.timebase().sample()?.monotonic;
    require(
        matches!(controller.advance_identity_dh(controller.scope(), port, now)?, Event::IdentityDhSubmitted(g) if g == original.generation()),
        "candidate did not admit its one original actual DH operation",
    )?;
    loop {
        within(deadline)?;
        match port.drive(Some(deadline)).await? {
            Step::Result { request, .. } => {
                require(
                    request == original,
                    "DH result selected a different original request",
                )?;
                let now = port.timebase().sample()?.monotonic;
                let event = controller.advance_identity_dh(controller.scope(), port, now)?;
                require(
                    matches!(event, Event::Candidate(_) | Event::Confirmed(_)),
                    "actual DH did not derive the original candidate",
                )?;
                require(
                    controller.pending_identity_dh().is_none(),
                    "actual result was not physically settled",
                )?;
                return Ok(());
            }
            Step::Native(progress) => native_progress(progress)?,
            Step::Lost { original, retired } => {
                let _diagnostic = writeln!(
                    io::stderr().lock(),
                    "PILS original-source loss retired-operations={}",
                    retired.iter().flatten().count()
                );
                native_progress(original)?;
                return Err("PILS original source lost before KX completion".into());
            }
            Step::Rejected { reason, .. } | Step::Closed(reason) => return Err(reason.into()),
            Step::IdentityChanged { .. } | Step::KeyChanged { .. } => {
                return Err("actual PILS public identity/MQ changed".into());
            }
            Step::Retired { .. } => return Err("original DH retired before a usable result".into()),
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Component fixture explicitly receives both original owners and modeled link endpoints"
)]
async fn encrypted_keepalive<'id, 'route, 'sender>(
    sender: &mut Controller<'_, '_, 'sender>,
    sender_book: &mut Book<'sender, '_, '_, 2>,
    receiver: &mut Controller<'id, '_, 'route>,
    receiver_book: &mut Book<'route, '_, '_, 2>,
    receiver_neighbor: Neighbor<'route>,
    timebase: &Timebase,
    entropy: &mut OsEntropy,
    deadline: Instant,
) -> Result<(), Failure> {
    within(deadline)?;
    // Real native elapsed time from the original shared epoch. The fixture's
    // due interval is1us; this sole finite sleep runs on the foreground runtime.
    tokio::time::sleep(Duration::from_millis(1)).await;
    within(deadline)?;
    let now = timebase.sample()?.monotonic;
    let route = sender_book.keepalive_due(now).ok_or(Error::NotReady)?;
    sender.keepalive(sender.scope(), route, sender_book, now)?;
    let mut wire = [0; CAPACITY];
    let (len, kind) = model_control(sender, sender_book, now, entropy, &mut wire)?;
    require(
        kind == Kind::KeepAlive,
        "expected a whole encrypted keepalive",
    )?;
    let connection::Event::Endpoint(input) =
        receiver_book.receive(receiver_neighbor, PeerMessage::decode(&wire[..len])?, now)?
    else {
        return Err("modeled connection did not authorize exact encrypted endpoint".into());
    };
    let mut plain = [0; CAPACITY];
    let received = receiver.open(receiver.scope(), input, &wire[..len], &mut plain)?;
    require(
        received.opened.bytes() == PLAIN
            && matches!(
                ChannelMessage::decode(received.opened.bytes())?,
                ChannelMessage::KeepAlive
            ),
        "whole header/body authentication or plaintext differs",
    )?;
    require(
        !received.promoted,
        "KX proofs had not already confirmed both endpoints",
    )?;
    Ok(())
}

async fn scenario<'id>(
    c_context: Context<'id>,
    r_context: Context<'id>,
    rust_identity: &'id Identity,
    port: &mut Port<'id, '_, '_, 2>,
    entropy: &mut OsEntropy,
    deadline: Instant,
) -> Result<(), Failure> {
    let c_peer = port.source().local();
    let r_peer = rust_identity.peer();
    let role = c_context.role();
    let timebase = port.timebase().clone();
    let now = timebase.sample()?.monotonic;
    let mut ci = connection::Instance::new();
    let mut ri = connection::Instance::new();
    let mut cn = [NeighborSlot::new(); 1];
    let mut rn = [NeighborSlot::new(); 1];
    let mut cr = [RouteSlot::<2>::new(); 1];
    let mut rr = [RouteSlot::<2>::new(); 1];
    let mut co = [];
    let mut ro = [];
    let mut cb = [0; CAPACITY];
    let mut rb = [0; CAPACITY];
    let mut cf = [FrameSlot::new(&mut cb)];
    let mut rf = [FrameSlot::new(&mut rb)];
    let limits = connection::Limits {
        frame_bytes: CAPACITY,
        keepalive_micros: 1,
        ..connection::Limits::default()
    };
    let mut c_book = Book::new(
        &mut ci, c_peer, &mut cn, &mut cr, &mut co, &mut cf, now, limits,
    )?;
    let mut r_book = Book::new(
        &mut ri, r_peer, &mut rn, &mut rr, &mut ro, &mut rf, now, limits,
    )?;
    let c_neighbor = c_book.neighbor_up(r_peer)?;
    let r_neighbor = r_book.neighbor_up(c_peer)?;
    c_book.neighbor_ready(c_neighbor, true)?;
    r_book.neighbor_ready(r_neighbor, true)?;
    let connection = connection::fresh_connection(entropy)?;
    let path = [c_peer, r_peer];
    c_book.open(
        PathPeers::new(&path),
        connection,
        Authentication::Unsigned,
        now,
    )?;
    let mut wire = [0; CAPACITY];
    let len = model_frame(&mut c_book, now, &mut wire)?;
    r_book.receive(r_neighbor, PeerMessage::decode(&wire[..len])?, now)?;
    let len = model_frame(&mut r_book, now, &mut wire)?;
    c_book.receive(c_neighbor, PeerMessage::decode(&wire[..len])?, now)?;
    require(
        c_book.select(r_peer).is_some() && r_book.select(c_peer).is_some(),
        "modeled route handshake did not finish",
    )?;
    let mut cs = Crypto::new();
    let mut rs = Crypto::new();
    let limits = tunnel::controller::Limits {
        crypto: tunnel::Limits {
            plaintext_bytes: 256,
            maximum_gap: 16,
        },
        negotiation_micros: 10_000_000,
        ..tunnel::controller::Limits::default()
    };
    let mut c = Controller::new_external_identity(
        c_context,
        port.source(),
        c_book.reset_authority(),
        cs.stores(),
        limits,
        now,
    )?;
    let mut r = Controller::new(
        r_context,
        rust_identity,
        r_book.reset_authority(),
        rs.stores(),
        limits,
        now,
    )?;
    let result = async {
        within(deadline)?;
        if role == Role::Alice {
            c.request(c.scope(), now, entropy)?;
            let (len, kind) = model_control(&mut c, &mut c_book, now, entropy, &mut wire)?;
            require(
                kind == Kind::KeyExchange,
                "Alice did not produce its original KX",
            )?;
            accept_control(&mut r, &mut r_book, r_neighbor, &wire[..len], now, entropy)?;
            let (len, kind) = model_control(&mut r, &mut r_book, now, entropy, &mut wire)?;
            require(
                kind == Kind::Authentication,
                "Betty did not produce its initial root proof",
            )?;
            accept_control(&mut c, &mut c_book, c_neighbor, &wire[..len], now, entropy)?;
            finish_dh(&mut c, port, deadline).await?;
            let now = timebase.sample()?.monotonic;
            let (len, _) = model_control(&mut c, &mut c_book, now, entropy, &mut wire)?;
            accept_control(&mut r, &mut r_book, r_neighbor, &wire[..len], now, entropy)?;
        } else {
            r.request(r.scope(), now, entropy)?;
            let (len, kind) = model_control(&mut r, &mut r_book, now, entropy, &mut wire)?;
            require(
                kind == Kind::KeyExchange,
                "Alice did not produce its original KX",
            )?;
            accept_control(&mut c, &mut c_book, c_neighbor, &wire[..len], now, entropy)?;
            finish_dh(&mut c, port, deadline).await?;
            let now = timebase.sample()?.monotonic;
            let (len, kind) = model_control(&mut c, &mut c_book, now, entropy, &mut wire)?;
            require(
                kind == Kind::Authentication,
                "PILS Betty did not produce its initial root proof",
            )?;
            accept_control(&mut r, &mut r_book, r_neighbor, &wire[..len], now, entropy)?;
            let (len, _) = model_control(&mut r, &mut r_book, now, entropy, &mut wire)?;
            accept_control(&mut c, &mut c_book, c_neighbor, &wire[..len], now, entropy)?;
        }
        require(
            c.snapshot().confirmed.is_some()
                && r.snapshot().confirmed.is_some()
                && c.snapshot().candidate.is_none()
                && r.snapshot().candidate.is_none(),
            "initial3-DH root proofs did not confirm both original roles",
        )?;
        encrypted_keepalive(
            &mut c,
            &mut c_book,
            &mut r,
            &mut r_book,
            r_neighbor,
            &timebase,
            entropy,
            deadline,
        )
        .await?;
        encrypted_keepalive(
            &mut r,
            &mut r_book,
            &mut c,
            &mut c_book,
            c_neighbor,
            &timebase,
            entropy,
            deadline,
        )
        .await?;
        Ok::<(), Failure>(())
    }
    .await;
    if result.is_err() {
        let retired = port.close();
        let _diagnostic = writeln!(
            io::stderr().lock(),
            "component failure physically stopped original source; retired-operations={}",
            retired.iter().flatten().count()
        );
    }
    let c_close = c.close(c.scope());
    let r_close = r.close(r.scope());
    let retirement = c.retire_identity_dh(c.scope(), port);
    if let Err(primary) = result {
        let _diagnostic = writeln!(
            io::stderr().lock(),
            "independent cleanup: local={c_close:?} remote-model={r_close:?} original-DH-retirement={retirement:?}"
        );
        return Err(primary);
    }
    require(
        c_close?.pending.is_none() && r_close?.pending.is_none(),
        "modeled original control output remained unretired",
    )?;
    retirement?;
    require(
        c.pending_identity_dh().is_none(),
        "original DH operation still needs physical retirement",
    )?;
    Ok(())
}

async fn run(path: PathBuf) -> Result<(), Failure> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let timebase = Timebase::new(clock.clone())?;
    let local = observe(path.clone(), clock.clone(), deadline).await?;
    let mut entropy = OsEntropy::new()?;
    let alice_remote = counterpart(local, Role::Alice, &mut entropy, deadline)?;
    let betty_remote = counterpart(local, Role::Betty, &mut entropy, deadline)?;
    // Two fixed registry rows are reused between roles while the one provider
    // and its copied original generation metadata remain alive.
    let context_domain = context::Instance::new();
    let mut context_rows = [const { context::Slot::new() }; 2];
    let mut context_registry = context::Registry::new(&context_domain, &mut context_rows)?;
    let mut native_instance = Instance::new();
    let source_domain = identity_dh::Instance::new();
    let mut source_rows = [const { identity_dh::Slot::new() }; 1];
    let mut source_registry = identity_dh::Registry::new(&source_domain, &mut source_rows)?;
    let mut jobs = [const { JobSlot::new() }; 1];
    let mut contexts = [ContextSlot::new(); 1];
    let mut startup = Connecting::<2>::new(
        &mut native_instance,
        EndpointSource::unix_with_clock(path, clock),
        local,
        Profile::Reference029,
        native_limits(),
        hello(),
    )?;
    loop {
        within(deadline)?;
        match startup.drive(Some(deadline)).await? {
            Progress::Inbound(Inbound::Identity { .. }) => break,
            progress => native_progress(progress)?,
        }
    }
    let mut port = startup
        .bind(&mut source_registry, &mut jobs, &mut contexts, timebase)
        .map_err(|r| r.reason)?;
    let result = async {
        let ac = context_registry.allocate(local, alice_remote.peer())?;
        let ar = context_registry.allocate(alice_remote.peer(), local)?;
        scenario(ac, ar, &alice_remote, &mut port, &mut entropy, deadline).await?;
        require(
            context_registry.available() == 2,
            "closed original role did not release registry rows",
        )?;
        let bc = context_registry.allocate(local, betty_remote.peer())?;
        let br = context_registry.allocate(betty_remote.peer(), local)?;
        scenario(bc, br, &betty_remote, &mut port, &mut entropy, deadline).await?;
        let report = port.report();
        require(
            report.submitted == 2
                && report.received == 2
                && report.consumed == 2
                && report.stopped == 0,
            "actual source did not consume exactly two original standard DH results",
        )?;
        Ok::<(), Failure>(())
    }
    .await;
    let retired = port.close();
    let report = port.report();
    if let Err(primary) = result {
        let _diagnostic = writeln!(
            io::stderr().lock(),
            "component original-source cleanup: report={report:?} retired-operations={}",
            retired.iter().flatten().count()
        );
        return Err(primary);
    }
    require(
        retired.iter().all(Option::is_none),
        "successful component retained an original PILS operation",
    )?;
    writeln!(
        io::stdout().lock(),
        "{{\"scope\":\"actual-c-pils-dh-pure-cadet-kx-aead-component\",\"core_link\":\"modeled\",\"c_cadet_started\":false,\"roles\":2,\"confirmed_initial_schedules\":2,\"sealed_and_opened_packets\":4,\"observer_mqs\":1,\"shared_dh_mqs\":1,\"actual_dh_submitted\":{},\"actual_dh_consumed\":{},\"original_source_stopped\":true,\"outstanding_operations\":0}}",
        report.submitted,
        report.consumed
    )?;
    Ok(())
}

fn main() -> Result<(), Failure> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or("usage: cadet_pils_kx PILS_UNIXPATH")?);
    require(args.next().is_none(), "unexpected extra arguments")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(path))
}
