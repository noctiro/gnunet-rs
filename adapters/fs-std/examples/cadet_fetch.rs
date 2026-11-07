//! Authenticate a complete CHK file through a real FS CADET serving endpoint.
//! Usage: cadet_fetch CADET_SOCKET PEER_HEX CHK_URI NEW_OUTPUT [TIMEOUT_MS]
use gnunet_cadet_host::{
    Channel, ChannelSlot, Client, EndpointSource, Instance, Limits, PortSlot, Received, Step,
    Transmit,
};
use gnunet_fs::{
    Content, Limits as UriLimits, Uri,
    content::{BLOCK_BYTES, BlockKey, FileReader, Layout},
};
use gnunet_wire::official::{
    fs::BlockType,
    fs_cadet::{PORT_LABEL, QUERY_BYTES, Query, Reply},
};
use std::{
    error::Error,
    fs::OpenOptions,
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::time::Instant;
type Failure = Box<dyn Error + Send + Sync>;

fn passive(step: Step<'_>) -> Result<(), Failure> {
    match step {
        Step::Activity { .. } | Step::Credit { .. } | Step::Ignored { .. } => Ok(()),
        Step::ConnectRetry { error, .. } => Err(error.into()),
        Step::Unavailable(error) => Err(error.into()),
        Step::Lost { cause, .. } => Err(format!("original CADET MQ lost: {cause:?}").into()),
        Step::Blocked { reason, .. } => Err(format!("CADET input refused: {reason}").into()),
        Step::WaitDeadline => {
            Err(io::Error::new(io::ErrorKind::TimedOut, "FS CADET observation deadline").into())
        }
        _ => Err("unexpected CADET event while fetching".into()),
    }
}
async fn written(
    client: &mut Client<'_, '_>,
    transmit: Transmit<'_>,
    deadline: Instant,
) -> Result<(), Failure> {
    loop {
        match client.drive(Some(deadline)).await? {
            Step::Written(done) if done.transmit == transmit => return Ok(()),
            step => passive(step)?,
        }
    }
}
async fn credit(
    client: &mut Client<'_, '_>,
    channel: Channel<'_>,
    deadline: Instant,
) -> Result<(), Failure> {
    while client.channel_info(channel)?.send_credit == 0 {
        passive(client.drive(Some(deadline)).await?)?;
    }
    Ok(())
}
async fn reply<'id>(
    client: &mut Client<'id, '_>,
    channel: Channel<'id>,
    deadline: Instant,
) -> Result<Received<'id>, Failure> {
    loop {
        match client.drive(Some(deadline)).await? {
            Step::Data(received) if received.channel() == channel => return Ok(received),
            step => passive(step)?,
        }
    }
}
async fn run(
    socket: PathBuf,
    peer: [u8; 32],
    content: Content,
    output: PathBuf,
    timeout: Duration,
) -> Result<(), Failure> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("timeout overflow")?;
    let mut instance = Instance::new();
    let mut ports: [PortSlot; 0] = [];
    let mut channels = [ChannelSlot::new(); 1];
    let mut client = Client::new(
        &mut instance,
        EndpointSource::unix(socket),
        &mut ports,
        &mut channels,
        Limits::default(),
    )?;
    loop {
        match client.drive(Some(deadline)).await? {
            Step::Connected(_) => break,
            step => passive(step)?,
        }
    }
    let channel = client.open(peer, gnunet_crypto::hash512(PORT_LABEL))?;
    let create = client
        .pending_transmit()
        .ok_or("missing original channel creation")?;
    written(&mut client, create, deadline).await?;
    let layout = Layout::new(content.size);
    let mut keys = vec![BlockKey::default(); layout.required_keys()];
    let mut reader = FileReader::new(content, &mut keys)?;
    let mut plaintext = [0; BLOCK_BYTES];
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut bytes = 0_u64;
    let mut data_blocks = 0_u64;
    let mut index_blocks = 0_u64;
    while let Some(node) = reader.next() {
        let kind = if node.node().level() == 0 {
            BlockType::DBLOCK
        } else {
            BlockType::IBLOCK
        };
        let mut request = [0; QUERY_BYTES];
        Query {
            block_type: kind,
            query: &node.key().query,
        }
        .encode(&mut request)?;
        credit(&mut client, channel, deadline).await?;
        let transmit = client.send(channel, 128 | 64 | 256, &request)?;
        written(&mut client, transmit, deadline).await?;
        let received = reply(&mut client, channel, deadline).await?;
        let block = Reply::decode(received.messages())?;
        if block.block_type != kind || gnunet_crypto::hash512(block.block) != node.key().query {
            return Err("actual FS reply mismatched its original channel/type/query".into());
        }
        if let Some(chunk) = reader.open_next(block.block, &mut plaintext)? {
            if chunk.range().start != bytes {
                return Err("authenticated file chunks arrived out of order".into());
            }
            target.write_all(chunk.bytes())?;
            bytes = chunk.range().end;
            data_blocks += 1;
        } else {
            index_blocks += 1;
        }
        let receipt = client.receive_done(received.delivery())?;
        written(&mut client, receipt, deadline).await?;
    }
    if reader.completion().map(|proof| proof.content()) != Some(content) || bytes != content.size {
        return Err("file lacked its original whole-tree authentication proof".into());
    }
    target.flush()?;
    let destroyed = client.destroy(channel)?;
    written(&mut client, destroyed, deadline).await?;
    if client
        .close()?
        .is_none_or(|loss| loss.channels != 0 || loss.pending.is_some())
    {
        return Err("native fetch did not retire its original channel and writes".into());
    }
    writeln!(
        io::stdout(),
        "{{\"event\":\"fs_cadet_authenticated_file\",\"bytes\":{bytes},\"data_blocks\":{data_blocks},\"index_blocks\":{index_blocks}}}"
    )?;
    Ok(())
}
fn peer(text: &str) -> Result<[u8; 32], Failure> {
    if text.len() != 64 {
        return Err("expected 64 hexadecimal peer digits".into());
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    let mut output = [0; 32];
    for (out, pair) in output.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *out = nibble(pair[0]).ok_or("invalid peer hex")? << 4
            | nibble(pair[1]).ok_or("invalid peer hex")?;
    }
    Ok(output)
}
fn main() -> Result<(), Failure> {
    let args: Vec<_> = std::env::args_os().collect();
    if !(5..=6).contains(&args.len()) {
        return Err(
            "usage: cadet_fetch CADET_SOCKET PEER_HEX CHK_URI NEW_OUTPUT [TIMEOUT_MS]".into(),
        );
    }
    let peer = peer(args[2].to_str().ok_or("invalid peer text")?)?;
    let timeout = args
        .get(5)
        .map(|value| {
            value
                .to_str()
                .ok_or("invalid timeout")?
                .parse::<u64>()
                .map_err(|_| "invalid timeout")
        })
        .transpose()?
        .unwrap_or(8000);
    if timeout == 0 {
        return Err("timeout must be nonzero".into());
    }
    let Uri::Content(content) = Uri::parse(
        args[3].to_str().ok_or("invalid URI text")?.as_bytes(),
        UriLimits::default(),
    )?
    else {
        return Err("expected an explicit original CHK URI".into());
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(
            PathBuf::from(&args[1]),
            peer,
            content,
            PathBuf::from(&args[4]),
            Duration::from_millis(timeout),
        ))
}
