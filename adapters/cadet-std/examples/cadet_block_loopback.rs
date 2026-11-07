//! Two native Rust CLIENT MQs through an unchanged official CADET own-peer loopback.
//! Usage: cadet_block_loopback UNIXPATH OWN_PEER_HEX
//! This is not a cross-peer tunnel or FS storage/publishing acceptance test.
use gnunet_cadet_host::{
    Channel, ChannelSlot, Client, Direction, EndpointSource, Instance, Limits, Port, PortSlot,
    Received, Step, Transmit,
    inspect::{self, Inspector, Query, Terminal},
};
use gnunet_fs::content::{encode_data, open_data};
use gnunet_wire::official::{
    AbsoluteTime,
    cadet::{CLIENT_CHANNEL_BOUNDARY, Response},
    fs::BlockType,
    fs_cadet::{self, Query as BlockQuery, Reply as BlockReply},
};
use std::{
    error::Error,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;

type Failure = Box<dyn Error + Send + Sync>;
const PLAINTEXT: &[u8] =
    b"GNUnet Rust native CADET own-peer loopback with an authenticated FS DBLOCK.";

#[derive(Default)]
struct Observations {
    connections: u64,
    local_writes: u64,
    service_credit_events: u64,
    ignored: u64,
}

fn passive(step: Step<'_>, observations: &mut Observations) -> Result<(), Failure> {
    match step {
        Step::Credit { available, .. } => {
            if available == 0 {
                return Err("service credit event did not expose a positive send window".into());
            }
            observations.service_credit_events += 1;
            Ok(())
        }
        Step::Activity { .. } => Ok(()),
        Step::Ignored { .. } => {
            observations.ignored += 1;
            Ok(())
        }
        Step::ConnectRetry { error, .. } => Err(error.into()),
        Step::Unavailable(error) => Err(error.into()),
        Step::Lost { cause, .. } => Err(format!("actual CADET MQ loss: {cause:?}").into()),
        Step::Blocked {
            reason,
            input_retained,
            ..
        } => Err(format!(
            "actual CADET resource refusal: {reason:?}, input_retained={input_retained}"
        )
        .into()),
        Step::WaitDeadline => Err("CADET observation deadline elapsed".into()),
        _ => Err("unexpected CADET event in this phase".into()),
    }
}

async fn connect(
    client: &mut Client<'_, '_>,
    deadline: Instant,
    observations: &mut Observations,
) -> Result<(), Failure> {
    loop {
        match client.drive(Some(deadline)).await? {
            Step::Connected(_) => {
                observations.connections += 1;
                return Ok(());
            }
            step => passive(step, observations)?,
        }
    }
}

async fn written<'id>(
    client: &mut Client<'id, '_>,
    transmit: Transmit<'id>,
    deadline: Instant,
    observations: &mut Observations,
) -> Result<(), Failure> {
    loop {
        match client.drive(Some(deadline)).await? {
            Step::Written(done) => {
                if done.transmit != transmit {
                    return Err("local completion selected another original transmission".into());
                }
                observations.local_writes += 1;
                return Ok(());
            }
            step => passive(step, observations)?,
        }
    }
}

async fn credit<'id>(
    client: &mut Client<'id, '_>,
    channel: Channel<'id>,
    deadline: Instant,
    observations: &mut Observations,
) -> Result<(), Failure> {
    while client.channel_info(channel)?.send_credit == 0 {
        passive(client.drive(Some(deadline)).await?, observations)?;
    }
    Ok(())
}

async fn receive<'id>(
    client: &mut Client<'id, '_>,
    channel: Channel<'id>,
    deadline: Instant,
    observations: &mut Observations,
) -> Result<Received<'id>, Failure> {
    loop {
        match client.drive(Some(deadline)).await? {
            Step::Data(received) => {
                if received.channel() != channel || received.priority() != 0 {
                    return Err("data belongs to another channel or priority".into());
                }
                return Ok(received);
            }
            step => passive(step, observations)?,
        }
    }
}

async fn incoming<'id>(
    client: &mut Client<'id, '_>,
    port: Port<'id>,
    peer: [u8; 32],
    hash: [u8; 64],
    deadline: Instant,
    observations: &mut Observations,
) -> Result<Channel<'id>, Failure> {
    loop {
        match client.drive(Some(deadline)).await? {
            Step::Incoming {
                channel,
                port: accepted,
            } => {
                let info = client.channel_info(channel)?;
                if accepted != port
                    || info.peer != peer
                    || info.port != hash
                    || info.direction != Direction::Incoming
                    || info.wire_id >= CLIENT_CHANNEL_BOUNDARY
                    || info.options != 0
                {
                    return Err("official incoming channel metadata mismatch".into());
                }
                return Ok(channel);
            }
            step => passive(step, observations)?,
        }
    }
}

async fn inspect(path: &Path, query: Query, deadline: Instant) -> Result<u64, Failure> {
    let mut inspector = Inspector::new(
        EndpointSource::unix(path.to_path_buf()),
        query,
        inspect::Limits::default(),
    )?;
    let mut entries = 0_u64;
    loop {
        match inspector.drive(Some(deadline)).await? {
            inspect::Step::Entry(entry) => {
                let valid = matches!(
                    (query, entry.response()?),
                    (Query::Peers, Response::PeerInfo { .. })
                        | (Query::Tunnels, Response::TunnelInfo { .. })
                        | (Query::Paths(_), Response::PathInfo { .. })
                );
                if !valid {
                    return Err("management entry type mismatch".into());
                }
                entries = entries
                    .checked_add(1)
                    .ok_or("management entry count overflow")?;
            }
            inspect::Step::Complete(end) => {
                let matching = matches!(
                    (query, end.response()?),
                    (Query::Peers, Response::PeersEnd)
                        | (Query::Tunnels, Response::TunnelsEnd)
                        | (Query::Paths(_), Response::PathsEnd)
                );
                let report = inspector.report();
                let query_bytes = if matches!(query, Query::Paths(_)) {
                    40
                } else {
                    4
                };
                if !matching
                    || !report.query_written
                    || report.written_bytes != query_bytes
                    || report.entries != entries
                    || report.terminal != Terminal::Complete
                {
                    return Err(
                        "management ended without its actual written query and matching END".into(),
                    );
                }
                if !matches!(
                    inspector.drive(Some(deadline)).await?,
                    inspect::Step::Closed
                ) {
                    return Err("completed inspector retained a live query MQ".into());
                }
                return Ok(entries);
            }
            inspect::Step::Connected
            | inspect::Step::Queued
            | inspect::Step::Activity
            | inspect::Step::Written { .. } => {}
            inspect::Step::Retry { cause, .. } => return Err(cause.into()),
            inspect::Step::Unavailable(error) => return Err(error.into()),
            inspect::Step::Interrupted { cause, report } => {
                return Err(format!(
                    "management interrupted before END: {cause}; partial={report:?}"
                )
                .into());
            }
            inspect::Step::WaitDeadline => return Err("management deadline without END".into()),
            inspect::Step::Closed => return Err("management closed without matching END".into()),
        }
    }
}

async fn run(path: PathBuf, own_peer: [u8; 32]) -> Result<(), Failure> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let port_hash = gnunet_crypto::hash512(fs_cadet::PORT_LABEL);
    let mut encrypted = [0; 1024];
    let encoded = encode_data(PLAINTEXT, &mut encrypted)?;
    let key = encoded.key();
    let mut query_bytes = [0; fs_cadet::QUERY_BYTES];
    let query_len = BlockQuery {
        block_type: BlockType::DBLOCK,
        query: &key.query,
    }
    .encode(&mut query_bytes)?;
    let expiry_micros = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?
        .checked_add(60_000_000)
        .ok_or("expiration overflow")?;
    let expiration = AbsoluteTime::from_micros(expiry_micros);
    let mut reply_bytes = [0; fs_cadet::REPLY_PREFIX + 1024];
    let reply_len = BlockReply {
        block_type: BlockType::DBLOCK,
        expiration,
        block: encoded.bytes(),
    }
    .encode(&mut reply_bytes)?;

    let mut listener_instance = Instance::new();
    let mut initiator_instance = Instance::new();
    let mut listener_ports = [PortSlot::new(); 1];
    let mut initiator_ports: [PortSlot; 0] = [];
    let mut listener_channels = [ChannelSlot::new(); 1];
    let mut initiator_channels = [ChannelSlot::new(); 1];
    let limits = Limits {
        frame_bytes: 4096,
        io_slice_bytes: 4096,
        max_payload_bytes: 1024,
        max_send_credit: 8,
    };
    let mut listener = Client::new(
        &mut listener_instance,
        EndpointSource::unix(path.clone()),
        &mut listener_ports,
        &mut listener_channels,
        limits,
    )?;
    let mut initiator = Client::new(
        &mut initiator_instance,
        EndpointSource::unix(path.clone()),
        &mut initiator_ports,
        &mut initiator_channels,
        limits,
    )?;
    let mut observations = Observations::default();
    connect(&mut listener, deadline, &mut observations).await?;
    connect(&mut initiator, deadline, &mut observations).await?;

    let port = listener.listen(port_hash)?;
    let announcement = listener
        .pending_transmit()
        .ok_or("missing port announcement frame")?;
    written(&mut listener, announcement, deadline, &mut observations).await?;
    if !listener.port_announced(port)? {
        return Err("port was not locally announced".into());
    }
    let outgoing = initiator.open(own_peer, port_hash)?;
    let creation = initiator
        .pending_transmit()
        .ok_or("missing channel creation frame")?;
    written(&mut initiator, creation, deadline, &mut observations).await?;
    let accepted = incoming(
        &mut listener,
        port,
        own_peer,
        port_hash,
        deadline,
        &mut observations,
    )
    .await?;
    let outgoing_info = initiator.channel_info(outgoing)?;
    if outgoing_info.direction != Direction::Outbound
        || outgoing_info.wire_id < CLIENT_CHANNEL_BOUNDARY
        || outgoing_info.peer != own_peer
        || outgoing_info.port != port_hash
    {
        return Err("official outgoing channel metadata mismatch".into());
    }

    credit(&mut initiator, outgoing, deadline, &mut observations).await?;
    let query_transmit = initiator.send(outgoing, 0, &query_bytes[..query_len])?;
    written(&mut initiator, query_transmit, deadline, &mut observations).await?;
    // Full local write above proves no remote processing: require actual DATA.
    let request = receive(&mut listener, accepted, deadline, &mut observations).await?;
    let query = BlockQuery::decode(request.messages())?;
    if query.block_type != BlockType::DBLOCK
        || query.query != &key.query
        || request.messages() != &query_bytes[..query_len]
    {
        return Err("actual FS query differs from requested DBLOCK key".into());
    }
    let request_done = request.delivery();
    drop(request);
    let query_ack = listener.receive_done(request_done)?;
    written(&mut listener, query_ack, deadline, &mut observations).await?;

    credit(&mut listener, accepted, deadline, &mut observations).await?;
    let reply_transmit = listener.send(accepted, 0, &reply_bytes[..reply_len])?;
    written(&mut listener, reply_transmit, deadline, &mut observations).await?;
    let answer = receive(&mut initiator, outgoing, deadline, &mut observations).await?;
    let reply = BlockReply::decode(answer.messages())?;
    if reply.block_type != BlockType::DBLOCK
        || reply.expiration != expiration
        || answer.messages() != &reply_bytes[..reply_len]
    {
        return Err("actual FS reply metadata or ciphertext differs".into());
    }
    let mut plaintext = [0; 1024];
    if open_data(key, reply.block, &mut plaintext)? != PLAINTEXT {
        return Err("authenticated DBLOCK plaintext differs".into());
    }
    let answer_done = answer.delivery();
    drop(answer);
    let reply_ack = initiator.receive_done(answer_done)?;
    written(&mut initiator, reply_ack, deadline, &mut observations).await?;

    let destruction = initiator.destroy(outgoing)?;
    written(&mut initiator, destruction, deadline, &mut observations).await?;
    loop {
        match listener.drive(Some(deadline)).await? {
            Step::Destroyed(channel) if channel == accepted => break,
            step => passive(step, &mut observations)?,
        }
    }
    if let Some(withdrawal) = listener.close_port(port)? {
        written(&mut listener, withdrawal, deadline, &mut observations).await?;
    }
    for client in [&mut listener, &mut initiator] {
        if let Some(loss) = client.close()?
            && (loss.channels != 0 || loss.pending.is_some())
        {
            return Err("client closed with unretired channel or local frame".into());
        }
        if !matches!(client.drive(Some(deadline)).await?, Step::Closed) {
            return Err("explicit client closure did not retire its physical MQ".into());
        }
    }

    // Each Inspector owns a separate actual MQ. Empty lists require real END.
    let peers = inspect(&path, Query::Peers, deadline).await?;
    let tunnels = inspect(&path, Query::Tunnels, deadline).await?;
    let paths = inspect(&path, Query::Paths(own_peer), deadline).await?;
    let summary = format!(
        "{{\"scope\":\"native-client-official-c-own-peer-loopback\",\"connections\":{},\"local_writes\":{},\"service_credit_events\":{},\"ignored\":{},\"query_bytes\":{query_len},\"reply_bytes\":{reply_len},\"authenticated_plaintext_bytes\":{},\"receive_done\":2,\"remote_destroy\":true,\"peers\":{peers},\"tunnels\":{tunnels},\"paths\":{paths},\"management_matching_ends\":3}}\n",
        observations.connections,
        observations.local_writes,
        observations.service_credit_events,
        observations.ignored,
        PLAINTEXT.len(),
    );
    io::stdout().write_all(summary.as_bytes())?;
    Ok(())
}

fn peer_hex(text: &str) -> Result<[u8; 32], Failure> {
    fn nibble(byte: u8) -> Result<u8, Failure> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err("own peer must be 64 hexadecimal digits".into()),
        }
    }
    if text.len() != 64 {
        return Err("own peer must be 64 hexadecimal digits".into());
    }
    let mut peer = [0; 32];
    for (out, pair) in peer.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(peer)
}

fn main() -> Result<(), Failure> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(
        args.next()
            .ok_or("usage: cadet_block_loopback UNIXPATH OWN_PEER_HEX")?,
    );
    let own_peer = args.next().ok_or("missing actual PILS own peer hex")?;
    let own_peer = peer_hex(own_peer.to_str().ok_or("own peer hex must be ASCII")?)?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(path, own_peer))
}
