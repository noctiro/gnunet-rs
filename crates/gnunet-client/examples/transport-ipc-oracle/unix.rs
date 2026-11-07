//! Native Unix socket observation for the portable codecs.
use super::*;
use gnunet_client::transport::{Event, Instance, SendId, SendOutcome, TransportClient};
use std::{
    io::{self, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if len < 4 {
        return Err("short frame".into());
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
fn serve(path: &Path) -> Result<(), Box<dyn Error>> {
    // Bind never removes or reuses an existing path. The harness owns this path.
    let listener = UnixListener::bind(path)?;
    let _path = SocketPath(path.to_owned());
    println!("READY");
    io::stdout().flush()?;
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(8)))?;
    let start = frame(&mut stream)?;
    if Request::decode(&start)? != Request::Start(Start::new(None, true)) {
        return Err("unexpected C START".into());
    }
    let mut buffer = [0; 128];
    let len = Response::Connected(PEER).encode(&mut buffer)?;
    for bytes in buffer[..len].chunks(3) {
        stream.write_all(bytes)?;
    }
    let sent = frame(&mut stream)?;
    if Request::decode(&sent)?
        != (Request::Send {
            peer: PEER,
            priority: 0,
            message: &MESSAGE,
        })
    {
        return Err("unexpected C SEND".into());
    }
    let len = Response::SendCredit(PEER).encode(&mut buffer)?;
    stream.write_all(&buffer[..len])?;
    let len = Response::Received {
        peer: PEER,
        message: &MESSAGE,
    }
    .encode(&mut buffer)?;
    for bytes in buffer[..len].chunks(3) {
        stream.write_all(bytes)?;
    }
    let continued = frame(&mut stream)?;
    if Request::decode(&continued)?
        != (Request::ReceiveContinue {
            peer: PEER,
            increase: 1,
        })
    {
        return Err("unexpected C RECV_OK".into());
    }
    let len = Response::Disconnected(PEER).encode(&mut buffer)?;
    stream.write_all(&buffer[..len])?;
    println!(
        "{{\"start\":1,\"send\":1,\"recv_ok\":1,\"connect\":1,\"send_ok\":1,\"recv\":1,\"disconnect\":1}}"
    );
    Ok(())
}
fn write_send<const P: usize, const S: usize, const R: usize>(
    stream: &mut UnixStream,
    owner: &mut TransportClient<'_, P, S, R>,
    id: SendId<'_>,
    bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut position = 0;
    while position < bytes.len() {
        let count = stream.write(&bytes[position..])?;
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero).into());
        }
        owner.send_bytes_written(id, count)?;
        position += count;
    }
    if owner.take_send_result(id)? != SendOutcome::Written {
        return Err("unexpected local SEND outcome".into());
    }
    Ok(())
}
fn probe(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let until = Instant::now() + Duration::from_secs(15);
    let mut instance = Instance::new();
    let mut owner = TransportClient::<4, 16, 16>::new(&mut instance, Start::new(None, true))?;
    let mut buffer = [0; 128];
    let (epoch, len) = owner.begin(&mut buffer)?;
    stream.write_all(&buffer[..len])?;
    let mut sent = 0;
    let mut received = 0;
    let mut credits = 0;
    let mut connected = 0;
    loop {
        if sent == 1 && received == 1 && credits >= 1 {
            break;
        }
        let remaining = until
            .checked_duration_since(Instant::now())
            .ok_or("probe deadline")?;
        stream.set_read_timeout(Some(remaining))?;
        let bytes = frame(&mut stream)?;
        match owner.receive(epoch, &bytes)? {
            Event::Connected(peer) => {
                connected += 1;
                if sent == 0 {
                    let (send, len) = owner.prepare_send(peer, 0, &MESSAGE, &mut buffer)?;
                    write_send(&mut stream, &mut owner, send, &buffer[..len])?;
                    sent += 1;
                }
            }
            Event::SendCredit(_) => credits += 1,
            Event::Received {
                receive, message, ..
            } => {
                if message != MESSAGE {
                    return Err("unexpected echoed payload".into());
                }
                received += 1;
                let len = owner.complete_receive(receive, &mut buffer)?;
                stream.write_all(&buffer[..len])?;
            }
            Event::Disconnected(_) => return Err("peer disconnected before round trip".into()),
            Event::LateSendCredit(_) => {}
        }
    }
    owner.connection_lost(epoch)?;
    println!(
        "{{\"connected\":{connected},\"sent\":{sent},\"received\":{received},\"send_credits\":{credits}}}"
    );
    Ok(())
}
pub(super) fn run(mode: &str, path: &Path) -> Result<(), Box<dyn Error>> {
    match mode {
        "serve" => serve(path),
        "probe" => probe(path),
        _ => Err("unknown TRANSPORT observer command".into()),
    }
}
