//! Actual private PILS/TRANSPORT streams and a retained loopback UDP socket.
//! Component coverage only; no official C node or remote UDP handshake is used.
use super::*;
use crate::addresses::{Addresses, Anchor};
use gnunet_client_host::EndpointSource;
use gnunet_pils::{Action, client::Inbound};
use gnunet_pils_host::client::{Limits, Progress};
use gnunet_service_runtime::{connection::Connection, local::Listener};
use gnunet_udp_communicator_host::{
    communicator::{Activity, Configuration},
    driver::{Capacity, Time},
    socket::DatagramSocket,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn pair() -> Result<(Connection, Connection), Cause> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr()?),
        listener.accept()
    );
    Ok((
        Connection::from_tcp(client?),
        Connection::from_tcp(server?.0),
    ))
}
async fn frame(stream: &mut Connection) -> Result<Vec<u8>, Cause> {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if size < 4 {
        return Err("invalid private fixture frame".into());
    }
    let mut frame = vec![0; size];
    frame[..4].copy_from_slice(&head);
    stream.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}
async fn announce<'id>(
    source: &mut Client<'id, 32>,
    listener: &Listener,
    addresses: &mut Addresses<'_, 'id>,
    announcement: &[u8],
) -> Result<(Observation<'id>, Connection), Cause> {
    let send = async {
        let (stream, _) = listener.accept().await?;
        let mut stream = Connection::from_unix(stream);
        stream.write_all(announcement).await?;
        Ok::<_, Cause>(stream)
    };
    let receive = async {
        loop {
            let progress = source.drive(None).await?;
            addresses.observe_pils(&progress)?;
            if let Progress::Inbound(Inbound::Identity { identity, .. }) = progress {
                return Ok::<_, Cause>(identity);
            }
        }
    };
    let (identity, stream) = tokio::join!(receive, send);
    Ok((identity?, stream?))
}
async fn lost<'id>(
    source: &mut Client<'id, 32>,
    addresses: &mut Addresses<'_, 'id>,
) -> Result<(Epoch<'id>, ConnectionLoss), Cause> {
    loop {
        let progress = source.drive(None).await?;
        addresses.observe_pils(&progress)?;
        if let Progress::Lost {
            epoch,
            cause,
            report,
        } = progress
        {
            if report.retained() != 0 || !source.is_idle() {
                return Err("unexpected retained crypto in observer fixture".into());
            }
            return cause
                .into_connection_loss()
                .map(|cause| (epoch, cause))
                .map_err(|cause| format!("unexpected fixture loss: {cause:?}").into());
        }
    }
}
struct Random;
impl gnunet_crypto::Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(bytes).map_err(|_| Error::Entropy)
    }
}
async fn case(changed_context: bool) -> Test {
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce)?;
    let scratch = Scratch(
        std::env::temp_dir().join(format!("udp-source-{:016x}", u64::from_be_bytes(nonce))),
    );
    gnunet_service_runtime::private_parents(&scratch.0.join(".owner"))?;
    let path = scratch.0.join("p");
    let listener = Listener::bind(&path)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let now = clock.sample()?.now;
    let limits = HelloLimits {
        maximum_input_bytes: 4096,
        maximum_address_bytes: 1024,
        maximum_addresses: 16,
    };
    let mut service = Service::<2048>::new(
        MasterKey::from_seed([17; 32]),
        Profile::ReferenceDeterministic,
        now.as_micros(),
        limits,
    )?;
    let mut instance = Instance::new();
    let mut source = Client::<32>::new(
        &mut instance,
        EndpointSource::unix_with_clock(path, clock.clone()),
        Profile::ReferenceDeterministic,
        Limits::default(),
        limits,
    )?;
    let mut addresses = Addresses::new(
        4,
        1024,
        Duration::from_secs(30),
        crate::HelloPublisher::Communicator,
    )?;
    let (original, mut stream) = announce(
        &mut source,
        &listener,
        &mut addresses,
        service.announcement(),
    )
    .await?;
    source.enable_local_key(MasterKey::from_seed([17; 32]))?;
    let socket = DatagramSocket::bind("127.0.0.1:0".parse()?, Default::default())?;
    let bound = socket.local_address();
    let transmit = socket.profile().sender_policy();
    addresses.replace_interfaces(&[bound], &mut |_| Ok(1))?;
    let namespace = Namespace::open(&scratch.0)?;
    let mut state = State::new(namespace, &source, 2, clock.clone(), now)?;
    let (connection, mut transport) = pair().await?;
    let mut owner = Communicator::new(
        connection,
        vec![socket],
        Configuration {
            local: state.binding()?.peer(),
            peers: 2,
            endpoints: 2,
            capacity: Capacity {
                frames: 4,
                bytes: 65535,
                io_slice: 1,
            },
            transmit,
        },
        100,
    )?;
    loop {
        if matches!(
            poll_fn(|cx| owner.poll_publications(cx)).await?,
            Activity::Registered
        ) {
            break;
        }
    }
    let register = frame(&mut transport).await?;
    if !matches!(
        gnunet_wire::official::communicator::Request::decode(&register)?,
        gnunet_wire::official::communicator::Request::Register { .. }
    ) {
        return Err("original REGISTER did not cross its real stream".into());
    }
    let anchor = Anchor {
        utc: now,
        native: std::time::Instant::now(),
    };
    while addresses.report().add_written == 0 {
        addresses.advance(&mut owner, &mut source, state.binding()?, Some(anchor))?;
        if addresses.report().pending_publication {
            poll_fn(|cx| owner.poll_publications(cx)).await?;
        }
    }
    let add = frame(&mut transport).await?;
    if !matches!(
        gnunet_wire::official::communicator::Request::decode(&add)?,
        gnunet_wire::official::communicator::Request::AddAddress { .. }
    ) {
        return Err("original address ADD did not wholly cross its stream".into());
    }
    while !addresses.report().pending_feed {
        addresses.advance(&mut owner, &mut source, state.binding()?, Some(anchor))?;
    }
    let written = async {
        loop {
            let progress = source.drive(None).await?;
            addresses.observe_pils(&progress)?;
            if addresses.report().feed_written == 1 {
                return Ok::<_, Cause>(());
            }
        }
    };
    let (written, feed) = tokio::join!(written, frame(&mut stream));
    written?;
    if !matches!(
        gnunet_wire::official::pils::Request::decode(&feed?)?,
        gnunet_wire::official::pils::Request::Feed { .. }
    ) || addresses.report().desired_feed_unsubmitted
    {
        return Err("original FEED whole-write was not separately observed".into());
    }
    let generation = owner.transport_generation();
    drop(stream);
    let (epoch, cause) = lost(&mut source, &mut addresses).await?;
    let cut = state
        .pause(epoch, cause, &mut owner)?
        .ok_or("original loss did not retire UDP authority")?;
    if !cut.transport_was_attached
        || !owner.identity_retired()
        || state.binding().is_ok()
        || state.ports().is_ok()
        || addresses.report().closing
        || addresses.report().claims != 1
    {
        return Err("source loss kept keys or erased address intent".into());
    }
    let mut tail = Vec::new();
    transport.read_to_end(&mut tail).await?;
    if !tail.is_empty() || DatagramSocket::bind(bound, Default::default()).is_ok() {
        return Err("old source survived or the original UDP socket was rebound".into());
    }
    owner
        .transport_loss()
        .ok_or("missing original TRANSPORT loss")?;
    addresses.transport_lost(&owner)?;
    let hard = state.window.as_ref().ok_or("missing recovery bound")?.hard;
    // A connected but unsigned successor cannot restore a key or journal.
    let (connected, accepted) = tokio::join!(source.drive(None), listener.accept());
    let progress = connected?;
    addresses.observe_pils(&progress)?;
    if !matches!(progress, Progress::Connected(_)) || !state.paused() || source.identity().is_some()
    {
        return Err("socket attachment became authority".into());
    }
    drop(accepted?.0);
    let (epoch, cause) = lost(&mut source, &mut addresses).await?;
    if state.pause(epoch, cause, &mut owner)?.is_some()
        || state.window.as_ref().is_none_or(|w| w.hard != hard)
        || !matches!(state.first_loss(), Some(ConnectionLoss::Eof))
    {
        return Err("repeated loss repeated retirement or renewed recovery".into());
    }
    if changed_context {
        let current = gnunet_wire::official::pils::PeerUpdate::decode(service.announcement())?;
        let mut block = current.block.to_vec();
        block.extend_from_slice(b"udp://127.0.0.1:4321\0");
        let mut request = vec![0; block.len() + 8];
        let len =
            gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut request)?;
        if !matches!(
            service.receive(
                &request[..len],
                &mut [0; 1024],
                now.as_micros(),
                &mut [0; 104]
            )?,
            Action::Broadcast {
                identity_changed: true
            }
        ) {
            return Err("changed signed context did not produce a new peer".into());
        }
    }
    let (latest, _stream) = announce(
        &mut source,
        &listener,
        &mut addresses,
        service.announcement(),
    )
    .await?;
    let current = clock.sample()?.now;
    if !latest.epoch().is_successor_of(epoch)
        || latest.revision() <= original.revision()
        || (latest.peer() != original.peer()) != changed_context
    {
        return Err("replacement lacked a real fresh identity".into());
    }
    if !state.select(&source, &mut owner, current, &mut |_| {
        Err("old source retired twice".into())
    })? || state.paused()
        || state.window.as_ref().is_none_or(|w| w.hard != hard)
    {
        return Err("verified replacement failed to restore a fresh key/journal".into());
    }
    let (connection, mut replacement) = pair().await?;
    owner.reconnect(connection)?;
    let mut random = Random;
    let mut registered = false;
    loop {
        let (binding, journal) = state.ports()?;
        let activity = poll_fn(|cx| {
            owner.poll_bound(
                cx,
                binding,
                &source,
                journal,
                Time {
                    now: 100,
                    utc: current,
                },
                &mut random,
                &mut |_| Ok(1),
            )
        })
        .await?;
        match activity {
            Activity::Registered => registered = true,
            Activity::Restored => break,
            _ => {}
        }
    }
    let _register = frame(&mut replacement).await?;
    if !registered
        || owner.transport_generation() <= generation
        || !state.restored()
        || state.window.is_some()
        || state.first_loss().is_some()
    {
        return Err(
            "recovery was credited before actual replacement registration/restoration".into(),
        );
    }
    if addresses.report().closing
        || addresses.report().claims != 1
        || !addresses.report().desired_feed_unsubmitted
        || owner.local_addresses().collect::<Vec<_>>() != vec![bound]
    {
        return Err("replacement lost the original address intent/socket".into());
    }
    owner.close();
    state.close();
    source.close();
    Ok(())
}
#[test]
fn native_source_recovery_requires_verified_identity_and_preserves_socket_intent_and_first_bound()
-> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                case(false).await?;
                case(true).await
            })
            .await?
        })
}
