//! Actual std socket/byte observer using production CORE application IPC owners.
#![expect(
    clippy::print_stdout,
    reason = "The observer records actual protocol output"
)]
use gnunet_client::core::{
    ClassOrder, CoreClient, Direction, Event, FULL_OUTBOUND, HEADER_INBOUND, HEADER_OUTBOUND,
    Instance, KxState, MessageTypes, Monitor, MonitorEvent, PeerClass, PeerId, PreparedFrame,
    Request, Response, SendOutcome, Traffic,
};
use gnunet_wire::official::{MessageHeader, message_type};
use std::{
    error::Error,
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const REMOTE: PeerId = PeerId([0x11; 32]);
const LOCAL: PeerId = PeerId([0x22; 32]);
const MESSAGE: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];
const ORDER: ClassOrder = ClassOrder::Little;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
fn vectors() -> Result<(), Box<dyn Error>> {
    let mut out = [0; 256];
    let mut rows = Vec::new();
    for (name, request) in [
        (
            "init",
            Request::Init {
                options: 0,
                types: MessageTypes::new(&[0]),
            },
        ),
        (
            "send_request",
            Request::SendRequest {
                priority: 0,
                deadline: 0,
                peer: REMOTE,
                size: 8,
                request_id: 1,
            },
        ),
        (
            "send",
            Request::Send {
                priority: 0,
                deadline: 0,
                peer: REMOTE,
                messages: &MESSAGE,
            },
        ),
        ("monitor_request", Request::Monitor),
    ] {
        let n = request.encode(&mut out)?;
        rows.push(format!("\"{name}\":\"{}\"", hex(&out[..n])));
    }
    for (name, response) in [
        (
            "init_reply",
            Response::InitReply {
                identity: LOCAL,
                class: PeerClass::SERVER,
            },
        ),
        (
            "connect",
            Response::Connected {
                peer: REMOTE,
                class: PeerClass::DESKTOP,
            },
        ),
        ("disconnect", Response::Disconnected(REMOTE)),
        (
            "inbound",
            Response::Traffic {
                direction: Direction::Inbound,
                peer: REMOTE,
                traffic: Traffic::Full(&MESSAGE),
            },
        ),
        (
            "outbound",
            Response::Traffic {
                direction: Direction::Outbound,
                peer: REMOTE,
                traffic: Traffic::Full(&MESSAGE),
            },
        ),
        (
            "inbound_header",
            Response::Traffic {
                direction: Direction::Inbound,
                peer: REMOTE,
                traffic: Traffic::Header(MessageHeader::new(message_type::TEST, 4)?),
            },
        ),
        (
            "outbound_header",
            Response::Traffic {
                direction: Direction::Outbound,
                peer: REMOTE,
                traffic: Traffic::Header(MessageHeader::new(message_type::TEST, 4)?),
            },
        ),
        (
            "send_ready",
            Response::SendReady {
                peer: REMOTE,
                request_id: 1,
                size: 8,
            },
        ),
        (
            "send_rejected",
            Response::SendReady {
                peer: REMOTE,
                request_id: 1,
                size: 0,
            },
        ),
        (
            "monitor_state",
            Response::Monitor {
                peer: REMOTE,
                state: KxState(4),
                timeout: 123,
            },
        ),
        (
            "monitor_end",
            Response::Monitor {
                peer: PeerId([0; 32]),
                state: KxState::SNAPSHOT_FINISHED,
                timeout: u64::MAX,
            },
        ),
    ] {
        let n = response.encode(&mut out, ORDER)?;
        rows.push(format!("\"{name}\":\"{}\"", hex(&out[..n])));
    }
    println!("{{{}}}", rows.join(","));
    Ok(())
}
fn decode(text: &str) -> Result<(), Box<dyn Error>> {
    let bytes = unhex(text)?;
    let mut out = vec![0; 65535];
    let (direction, n) = match Request::decode(&bytes) {
        Ok(request) => ("request", request.encode(&mut out)?),
        Err(gnunet_types::Error::Unsupported) => (
            "response",
            Response::decode(&bytes, ORDER)?.encode(&mut out, ORDER)?,
        ),
        Err(error) => return Err(error.into()),
    };
    println!(
        "{{\"direction\":\"{direction}\",\"reencoded\":\"{}\"}}",
        hex(&out[..n])
    );
    Ok(())
}
fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if len < 4 {
        return Err("invalid frame size".into());
    }
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..])?;
    Ok(bytes)
}
struct SocketPath(PathBuf);
impl Drop for SocketPath {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}
fn respond(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Box<dyn Error>> {
    let mut out = [0; 256];
    let n = response.encode(&mut out, ORDER)?;
    for bytes in out[..n].chunks(3) {
        stream.write_all(bytes)?;
    }
    Ok(())
}
fn serve(path: &Path, monitor: bool) -> Result<(), Box<dyn Error>> {
    let listener = UnixListener::bind(path)?;
    let _path = SocketPath(path.to_owned());
    println!("READY");
    io::stdout().flush()?;
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(8)))?;
    let first = frame(&mut stream)?;
    if monitor {
        if Request::decode(&first)? != Request::Monitor {
            return Err("expected CORE_MONITOR_PEERS".into());
        }
        respond(
            &mut stream,
            Response::Monitor {
                peer: REMOTE,
                state: KxState(4),
                timeout: 123,
            },
        )?;
        respond(
            &mut stream,
            Response::Monitor {
                peer: PeerId([0; 32]),
                state: KxState::SNAPSHOT_FINISHED,
                timeout: u64::MAX,
            },
        )?;
        respond(
            &mut stream,
            Response::Monitor {
                peer: REMOTE,
                state: KxState(7),
                timeout: 456,
            },
        )?;
        // The public monitor cancels its original socket after the post-snapshot update.
        let mut end = [0; 1];
        if stream.read(&mut end)? != 0 {
            return Err("unexpected monitor request tail".into());
        }
        println!("{{\"monitor_request\":1,\"updates\":2,\"snapshot\":1}}");
        return Ok(());
    }
    if Request::decode(&first)?
        != (Request::Init {
            options: 0,
            types: MessageTypes::new(&[0]),
        })
    {
        return Err("unexpected CORE_INIT".into());
    }
    respond(
        &mut stream,
        Response::InitReply {
            identity: LOCAL,
            class: PeerClass::SERVER,
        },
    )?;
    respond(
        &mut stream,
        Response::Connected {
            peer: REMOTE,
            class: PeerClass::DESKTOP,
        },
    )?;
    let requested = frame(&mut stream)?;
    if Request::decode(&requested)?
        != (Request::SendRequest {
            priority: 0,
            deadline: 0,
            peer: REMOTE,
            size: 8,
            request_id: 1,
        })
    {
        return Err("unexpected CORE_SEND_REQUEST".into());
    }
    respond(
        &mut stream,
        Response::SendReady {
            peer: REMOTE,
            request_id: 1,
            size: 8,
        },
    )?;
    let sent = frame(&mut stream)?;
    if Request::decode(&sent)?
        != (Request::Send {
            priority: 0,
            deadline: 0,
            peer: REMOTE,
            messages: &MESSAGE,
        })
    {
        return Err("unexpected CORE_SEND".into());
    }
    respond(
        &mut stream,
        Response::Traffic {
            direction: Direction::Inbound,
            peer: REMOTE,
            traffic: Traffic::Full(&MESSAGE),
        },
    )?;
    respond(&mut stream, Response::Disconnected(REMOTE))?;
    println!(
        "{{\"init\":1,\"request\":1,\"send\":1,\"init_reply\":1,\"connect\":1,\"ready\":1,\"inbound\":1,\"disconnect\":1}}"
    );
    Ok(())
}
fn write_prepared<const P: usize, const S: usize>(
    stream: &mut UnixStream,
    owner: &mut CoreClient<'_, P, S>,
    frame: PreparedFrame<'_, '_>,
) -> Result<(), Box<dyn Error>> {
    let mut written = 0;
    while written < frame.bytes().len() {
        let count = stream.write(&frame.bytes()[written..])?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero).into());
        }
        owner.payload_bytes_written(frame.send(), count)?;
        written += count;
    }
    Ok(())
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ProbeProfile {
    Inbound,
    Outbound,
    Headers,
}
fn probe(path: &Path, monitor: bool, profile: ProbeProfile) -> Result<(), Box<dyn Error>> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let until = Instant::now() + Duration::from_secs(15);
    let mut instance = Instance::new();
    let mut out = [0; 256];
    if monitor {
        let mut owner = Monitor::new(&mut instance);
        let (epoch, n) = owner.begin(&mut out)?;
        stream.write_all(&out[..n])?;
        let mut updates = 0;
        loop {
            stream.set_read_timeout(Some(
                until
                    .checked_duration_since(Instant::now())
                    .ok_or("monitor deadline")?,
            ))?;
            let bytes = frame(&mut stream)?;
            match owner.receive(epoch, &bytes)? {
                MonitorEvent::SnapshotFinished => break,
                MonitorEvent::Update { .. } => updates += 1,
                MonitorEvent::ServiceLost => return Err("unexpected local loss event".into()),
            }
        }
        drop(stream);
        owner.connection_lost(epoch)?;
        println!("{{\"monitor_request\":1,\"updates\":{updates},\"snapshot\":1}}");
        return Ok(());
    }
    let (options, types): (_, &[u16]) = match profile {
        ProbeProfile::Inbound => (0, &[0]),
        ProbeProfile::Outbound => (FULL_OUTBOUND, &[0]),
        // Current C treats no subscriptions plus observation flags as an inbound
        // wildcard and emits full data. A nonmatching type selects real previews.
        ProbeProfile::Headers => (HEADER_INBOUND | HEADER_OUTBOUND, &[1]),
    };
    let mut owner = CoreClient::<8, 8>::new(&mut instance, ORDER, options, types)?;
    let (epoch, n) = owner.begin(&mut out)?;
    stream.write_all(&out[..n])?;
    let mut operation = None;
    let mut sent = 0;
    let mut received = 0;
    let mut outbound = 0;
    let mut inbound_header = 0;
    let mut outbound_header = 0;
    let mut ready = 0;
    let mut local_identity = None;
    loop {
        stream.set_read_timeout(Some(
            until
                .checked_duration_since(Instant::now())
                .ok_or("application deadline")?,
        ))?;
        let bytes = frame(&mut stream)?;
        match owner.receive(epoch, &bytes)? {
            Event::Ready { local, .. } => {
                local_identity = Some(local.identity());
                let (original, n) = owner
                    .request_send(local, 0, 0, MESSAGE.to_vec(), &mut out)
                    .map_err(|rejected| rejected.reason)?;
                stream.write_all(&out[..n])?;
                operation = Some(original);
            }
            Event::SendReady { send, .. } => {
                let original = operation
                    .as_ref()
                    .ok_or("READY without original operation")?;
                if original.id() != send {
                    return Err("READY original identity mismatch".into());
                }
                let prepared = owner.prepare_payload(original, &mut out)?;
                write_prepared(&mut stream, &mut owner, prepared)?;
                let original = operation.take().ok_or("original disappeared")?;
                let completion = owner.finish(original).map_err(|rejected| rejected.reason)?;
                if completion.outcome != SendOutcome::Written {
                    return Err("unexpected local payload outcome".into());
                }
                sent += 1;
                ready += 1;
            }
            Event::Traffic {
                direction,
                peer,
                traffic,
                ..
            } => {
                if Some(peer) != local_identity {
                    return Err("unexpected loopback peer".into());
                }
                match traffic {
                    Traffic::Full(message) => {
                        if profile == ProbeProfile::Headers || message != MESSAGE {
                            return Err("unexpected loopback payload".into());
                        }
                        match direction {
                            Direction::Inbound => received += 1,
                            Direction::Outbound => outbound += 1,
                        }
                    }
                    Traffic::Header(header) => {
                        if profile != ProbeProfile::Headers
                            || header.size() != MESSAGE.len()
                            || header.message_type() != message_type::TEST
                        {
                            return Err("unexpected loopback header preview".into());
                        }
                        match direction {
                            Direction::Inbound => inbound_header += 1,
                            Direction::Outbound => outbound_header += 1,
                        }
                    }
                }
            }
            Event::Rejected(_) => return Err("service rejected loopback request".into()),
            _ => {}
        }
        let complete = match profile {
            ProbeProfile::Inbound => received == 1,
            ProbeProfile::Outbound => received == 1 && outbound == 1,
            ProbeProfile::Headers => inbound_header == 1 && outbound_header == 1,
        };
        if sent == 1 && complete {
            break;
        }
    }
    drop(stream);
    owner.connection_lost(epoch)?;
    println!(
        "{{\"ready\":{ready},\"sent\":{sent},\"received\":{received},\"outbound\":{outbound},\"inbound_header\":{inbound_header},\"outbound_header\":{outbound_header}}}"
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("vectors"), None) => vectors(), (Some("decode"), Some(bytes)) => decode(bytes),
        (Some("serve"), Some(path)) => serve(Path::new(path), false),
        (Some("serve-monitor"), Some(path)) => serve(Path::new(path), true),
        (Some("probe"), Some(path)) => probe(Path::new(path), false, ProbeProfile::Inbound),
        (Some("probe-outbound"), Some(path)) => probe(Path::new(path), false, ProbeProfile::Outbound),
        (Some("probe-headers"), Some(path)) => probe(Path::new(path), false, ProbeProfile::Headers),
        (Some("probe-monitor"), Some(path)) => probe(Path::new(path), true, ProbeProfile::Inbound),
        _ => Err("vectors | decode HEX | serve PATH | serve-monitor PATH | probe PATH | probe-outbound PATH | probe-headers PATH | probe-monitor PATH".into()),
    }
}
