//! Finite actual child fixture for inherited listener/backlog observation only.
//! This is not the ARM native launcher or any GNUnet application readiness claim.
use gnunet_service_runtime::{ActivatedSocket, capture};
use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};
fn echo(mut stream: impl Read + Write) -> io::Result<()> {
    let mut input = [0; 5];
    stream.read_exact(&mut input)?;
    if &input != b"queue" {
        return Err(io::ErrorKind::InvalidData.into());
    }
    stream.write_all(b"child:queue")
}
#[expect(
    unsafe_code,
    reason = "The fixture captures only its exclusively inherited offered stdin listener at the first instruction, before other resource/runtime/config construction"
)]
fn main() -> io::Result<()> {
    // SAFETY: this is the first instruction in a fresh single-threaded exec. The
    // parent offered only fd0 via Command stdin, with no Rust fd owner in child.
    let mut activation = unsafe { capture() }?;
    if activation.sockets.len() != 1 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let Some(socket) = activation.sockets.pop() else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let result = match &socket {
            ActivatedSocket::Unix(listener) => listener.accept().and_then(|(stream, _)| {
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                echo(stream)
            }),
            ActivatedSocket::Tcp(listener) => listener.accept().and_then(|(stream, _)| {
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                echo(stream)
            }),
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(error),
        }
    }
}
