//! Production FS Router through an owned unchanged C CADET own-peer daemon.
//! Usage: cadet_route UNIXPATH OWN_PEER_HEX
//! This profile covers actual native direct routing, not cross-peer CADET.
use gnunet_cadet_host::{
    Channel, ChannelSlot, Client, Direction, EndpointSource, Instance, Limits as NativeLimits,
    PortSlot, Received, Step, Transmit,
};
use gnunet_fs::content::{BlockKey, encode_data, open_data};
use gnunet_fs_host::server::{
    PeerProgress, PeerRouter, RouteAdmission,
    cadet::{Limits, Router},
};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_wire::official::{
    AbsoluteTime,
    fs::{BlockType, Search},
    fs_cadet::{self, Query, Reply},
};
use std::{
    error::Error,
    future::poll_fn,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

type Failure = Box<dyn Error + Send + Sync>;
const PLAINTEXT: &[u8] = b"Production Rust FS direct CADET router, real C own-peer loopback.";
const ROUTE: u64 = 4;

enum Event<'id> {
    Listener(Step<'id>),
    Router(PeerProgress),
}

/// Poll both original owners before sleeping; alternate the first polled side
/// after every event so one client's writable stream cannot starve the other.
async fn next<'id>(
    listener: &mut Client<'id, '_>,
    router: &mut Router<'_, '_>,
    deliver: bool,
    deadline: Instant,
    turn: &mut bool,
) -> Result<Event<'id>, Failure> {
    poll_fn(|cx| {
        if Instant::now() >= deadline {
            return Poll::Ready(Err("FS direct CADET profile deadline elapsed".into()));
        }
        for offset in 0..2 {
            let side = (usize::from(*turn) + offset) % 2;
            if side == 0 {
                match listener.poll(cx, Some(deadline)) {
                    Poll::Pending => {}
                    Poll::Ready(result) => {
                        *turn = true;
                        return Poll::Ready(
                            result
                                .map(Event::Listener)
                                .map_err(|error| Box::new(error) as Failure),
                        );
                    }
                }
            } else {
                match PeerRouter::poll(router, cx, deliver) {
                    Poll::Pending => {}
                    Poll::Ready(result) => {
                        *turn = false;
                        return Poll::Ready(
                            result
                                .map(Event::Router)
                                .map_err(|error| Box::new(error) as Failure),
                        );
                    }
                }
            }
        }
        Poll::Pending
    })
    .await
}

fn passive(step: Step<'_>) -> Result<(), Failure> {
    match step {
        Step::Credit { available, .. } if available != 0 => Ok(()),
        Step::Activity { .. } | Step::Ignored { .. } => Ok(()),
        Step::ConnectRetry { error, .. } => Err(error.into()),
        Step::Unavailable(error) => Err(error.into()),
        Step::Lost { cause, .. } => Err(format!("actual listener MQ loss: {cause:?}").into()),
        Step::Blocked { reason, .. } => {
            Err(format!("actual listener resource refusal: {reason:?}").into())
        }
        Step::WaitDeadline => Err("actual listener observation deadline".into()),
        _ => Err("unexpected listener event in this profile phase".into()),
    }
}

struct Serving<'id> {
    channel: Option<Channel<'id>>,
    query: Option<Received<'id>>,
    query_ack: Option<Transmit<'id>>,
    query_done: bool,
    reply_write: Option<Transmit<'id>>,
    reply_written: bool,
    queries: u64,
    destroyed: bool,
}
impl<'id> Serving<'id> {
    fn new() -> Self {
        Self {
            channel: None,
            query: None,
            query_ack: None,
            query_done: false,
            reply_write: None,
            reply_written: false,
            queries: 0,
            destroyed: false,
        }
    }
    fn advance(&mut self, listener: &mut Client<'id, '_>, reply: &[u8]) -> Result<(), Failure> {
        if listener.pending_transmit().is_some() {
            return Ok(());
        }
        if let Some(query) = &self.query {
            self.query_ack = Some(listener.receive_done(query.delivery())?);
            self.query = None;
        } else if self.query_done && self.reply_write.is_none() && !self.reply_written {
            let channel = self
                .channel
                .ok_or("query lacks its actual incoming channel")?;
            if listener.channel_info(channel)?.send_credit != 0 {
                self.reply_write = Some(listener.send(channel, 0, reply)?);
            }
        }
        Ok(())
    }
    fn observe(
        &mut self,
        listener: &Client<'id, '_>,
        step: Step<'id>,
        own_peer: [u8; 32],
        key: BlockKey,
    ) -> Result<(), Failure> {
        match step {
            Step::Incoming { channel, port } => {
                let info = listener.channel_info(channel)?;
                let expected_port = gnunet_crypto::hash512(fs_cadet::PORT_LABEL);
                if self.channel.is_some()
                    || info.direction != Direction::Incoming
                    || info.peer != own_peer
                    || info.port != expected_port
                    || listener.port_hash(port)? != expected_port
                {
                    return Err("actual incoming direct route metadata mismatch".into());
                }
                self.channel = Some(channel);
            }
            Step::Data(received) => {
                if Some(received.channel()) != self.channel || self.queries != 0 {
                    return Err("unexpected original query channel/count".into());
                }
                // The pinned C loopback creates a fresh LocalData envelope;
                // outgoing MQ preferences are not a received identity field.
                let query = Query::decode(received.messages())?;
                if query.block_type != BlockType::DBLOCK || *query.query != key.query {
                    return Err("actual Router query differs from its original CHK query".into());
                }
                self.queries += 1;
                self.query = Some(received);
            }
            Step::Written(written) if Some(written.transmit) == self.query_ack => {
                self.query_ack = None;
                self.query_done = true;
            }
            Step::Written(written) if Some(written.transmit) == self.reply_write => {
                self.reply_write = None;
                self.reply_written = true;
            }
            Step::Destroyed(channel) if Some(channel) == self.channel => {
                self.destroyed = true;
            }
            step => passive(step)?,
        }
        Ok(())
    }
}

struct Scenario<'a> {
    own_peer: [u8; 32],
    clock: &'a Arc<dyn RuntimeClock>,
    key: BlockKey,
    reply: &'a [u8],
    expiration: AbsoluteTime,
    deadline: Instant,
}
async fn exercise(
    listener: &mut Client<'_, '_>,
    router: &mut Router<'_, '_>,
    scenario: Scenario<'_>,
) -> Result<(), Failure> {
    let Scenario {
        own_peer,
        clock,
        key,
        reply,
        expiration,
        deadline,
    } = scenario;
    // Establish and announce the real listening port before any eligible route.
    loop {
        match listener.drive(Some(deadline)).await? {
            Step::Connected(_) => break,
            step => passive(step)?,
        }
    }
    let port = listener.listen(gnunet_crypto::hash512(fs_cadet::PORT_LABEL))?;
    let announcement = listener
        .pending_transmit()
        .ok_or("missing port announcement")?;
    loop {
        match listener.drive(Some(deadline)).await? {
            Step::Written(written) if written.transmit == announcement => break,
            step => passive(step)?,
        }
    }
    if !listener.port_announced(port)? {
        return Err("actual listener port announcement was not written".into());
    }
    let search = Search {
        options: 0,
        block_type: BlockType::DBLOCK,
        anonymity: 0,
        target: own_peer,
        query: key.query,
        seen: &[],
    };
    if !matches!(
        router.start(
            1,
            Search {
                anonymity: 1,
                ..search
            },
            &[]
        )?,
        RouteAdmission::Idle
    ) || !matches!(
        router.start(
            2,
            Search {
                target: [0; 32],
                ..search
            },
            &[]
        )?,
        RouteAdmission::Idle
    ) {
        return Err("unsupported anonymous/unknown-holder route caused a peer effect".into());
    }
    // Cancellation before any owner poll must not put a query on the MQ.
    if !matches!(router.start(3, search, &[])?, RouteAdmission::Queued) {
        return Err("direct pre-exposure cancellation route was not admitted".into());
    }
    router.cancel(3)?;
    let before = clock.sample()?.now.as_micros();
    if !matches!(router.start(ROUTE, search, &[])?, RouteAdmission::Queued) {
        return Err("actual positive route was not admitted".into());
    }
    let mut turn = false;
    let mut serving = Serving::new();
    while router.retained_results() == 0 {
        serving.advance(listener, reply)?;
        match next(listener, router, false, deadline, &mut turn).await? {
            Event::Listener(step) => serving.observe(listener, step, own_peer, key)?,
            Event::Router(PeerProgress::Activity) => {}
            Event::Router(PeerProgress::Ended(_)) => {
                return Err("direct route ended before its matching positive block".into());
            }
            Event::Router(_) => {
                return Err("provider delivered a result while deliver=false".into());
            }
        }
    }
    if router.retained_results() != 1 || !serving.reply_written || serving.queries != 1 {
        return Err("positive was not actually retained after one original written reply".into());
    }
    // Repeated false polls must preserve the same actual result, while native
    // IO remains enabled. No sleep or assumed packet arrival establishes this.
    poll_fn(|cx| match PeerRouter::poll(router, cx, false) {
        Poll::Ready(Err(error)) => Poll::Ready(Err(Box::new(error) as Failure)),
        Poll::Ready(Ok(PeerProgress::Activity)) | Poll::Pending => Poll::Ready(Ok(())),
        Poll::Ready(Ok(_)) => Poll::Ready(Err::<(), Failure>(
            "false poll consumed a retained result".into(),
        )),
    })
    .await?;
    if router.retained_results() != 1 {
        return Err("false poll lost the original candidate".into());
    }
    loop {
        serving.advance(listener, reply)?;
        match next(listener, router, true, deadline, &mut turn).await? {
            Event::Listener(step) => serving.observe(listener, step, own_peer, key)?,
            Event::Router(PeerProgress::Activity) => {}
            Event::Router(PeerProgress::CadetReply {
                route,
                frame,
                metadata,
            }) => {
                let received = Reply::decode(frame.bytes())?;
                let now = clock.sample()?.now.as_micros();
                if route != ROUTE
                    || frame.bytes() != reply
                    || received.block_type != BlockType::DBLOCK
                    || received.expiration != expiration
                    || gnunet_crypto::hash512(received.block) != key.query
                    || metadata.num_transmissions != 1
                    || metadata.respect_offered != 0
                    || metadata.last_transmission.as_micros() < before
                    || metadata.last_transmission.as_micros() > now
                {
                    return Err(
                        "actual Router result frame/owner/local observations mismatch".into(),
                    );
                }
                let mut plaintext = [0; 1024];
                if open_data(key, received.block, &mut plaintext)? != PLAINTEXT {
                    return Err(
                        "actual Router block failed CHK/AEAD/plaintext authentication".into(),
                    );
                }
                router.cancel(ROUTE)?;
                break;
            }
            Event::Router(_) => {
                return Err("direct route produced a different local outcome".into());
            }
        }
    }
    while !serving.destroyed {
        match next(listener, router, true, deadline, &mut turn).await? {
            Event::Listener(step) => serving.observe(listener, step, own_peer, key)?,
            Event::Router(PeerProgress::Activity | PeerProgress::Ended(ROUTE)) => {}
            Event::Router(_) => {
                return Err("cleanup produced an extra positive/unknown owner".into());
            }
        }
    }
    if serving.queries != 1
        || router.retained_results() != 0
        || router.report().losses != 0
        || router.report().timeouts != 0
    {
        return Err("profile ended with extra queries, retained results or route losses".into());
    }
    Ok(())
}

async fn run(path: PathBuf, peer: [u8; 32]) -> Result<(), Failure> {
    let deadline = Instant::now() + Duration::from_secs(12);
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let mut encrypted = [0; 1024];
    let encoded = encode_data(PLAINTEXT, &mut encrypted)?;
    let key = encoded.key();
    let expiration = AbsoluteTime::from_micros(
        clock
            .sample()?
            .now
            .as_micros()
            .checked_add(60_000_000)
            .ok_or("expiry overflow")?,
    );
    let mut reply = [0; 1024 + fs_cadet::REPLY_PREFIX];
    let length = Reply {
        block_type: BlockType::DBLOCK,
        expiration,
        block: encoded.bytes(),
    }
    .encode(&mut reply)?;
    let mut listener_id = Instance::new();
    let mut router_id = Instance::new();
    let mut listener_ports = [PortSlot::new(); 1];
    let mut router_ports: [PortSlot; 0] = [];
    let mut listener_channels = [ChannelSlot::new(); 2];
    let mut router_channels = [ChannelSlot::new(); 2];
    let native = NativeLimits {
        frame_bytes: 4096,
        io_slice_bytes: 4096,
        max_payload_bytes: 2048,
        max_send_credit: 8,
    };
    let mut listener = Client::new(
        &mut listener_id,
        EndpointSource::unix_with_clock(path.clone(), clock.clone()),
        &mut listener_ports,
        &mut listener_channels,
        native,
    )?;
    let client = Client::new(
        &mut router_id,
        EndpointSource::unix_with_clock(path, clock.clone()),
        &mut router_ports,
        &mut router_channels,
        native,
    )?;
    let mut router = Router::new(
        client,
        Limits {
            routes: 2,
            timeout: Duration::from_secs(8),
        },
    )?;
    if !Arc::ptr_eq(&router.clock(), &clock) {
        return Err("Router changed the explicitly shared endpoint clock".into());
    }
    let result = exercise(
        &mut listener,
        &mut router,
        Scenario {
            own_peer: peer,
            clock: &clock,
            key,
            reply: &reply[..length],
            expiration,
            deadline,
        },
    )
    .await;
    // Explicit cleanup runs for either profile success or a meaningful refusal.
    let router_closed = router.close();
    let listener_closed = listener.close();
    result?;
    router_closed?;
    let retired = listener_closed?.ok_or("listener did not retire its actual connected MQ")?;
    if retired.channels != 0 || retired.pending.is_some() {
        return Err(
            "actual listener cleanup retained a channel or uncompleted original write".into(),
        );
    }
    io::stdout().write_all(b"{\"status\":\"passed\",\"scope\":\"production FS direct Router through actual official C own-peer CADET\",\"queries\":1,\"unsupported_routes_idle\":2,\"pre_exposure_cancel\":true,\"original_type141_retained_under_backpressure\":true,\"local_written_metadata\":true,\"chk_aead_authenticated\":true,\"remote_destroy_observed\":true,\"explicit_native_cleanup\":true,\"cross_peer\":false}\n")?;
    Ok(())
}

fn peer(text: &str) -> Result<[u8; 32], Failure> {
    fn nibble(value: u8) -> Result<u8, Failure> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err("peer identity must contain only hexadecimal digits".into()),
        }
    }
    if text.len() != 64 {
        return Err("peer identity must be 32 public bytes in hex".into());
    }
    let mut result = [0; 32];
    for (output, input) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *output = (nibble(input[0])? << 4) | nibble(input[1])?;
    }
    Ok(result)
}

fn main() -> Result<(), Failure> {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 3 {
        return Err("usage: cadet_route UNIXPATH OWN_PEER_HEX".into());
    }
    let own_peer = peer(arguments[2].to_str().ok_or("peer hex is not valid UTF-8")?)?;
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(PathBuf::from(&arguments[1]), own_peer));
    if let Err(error) = &result {
        let _printed = writeln!(io::stderr(), "cadet_route: {error}");
    }
    result
}
