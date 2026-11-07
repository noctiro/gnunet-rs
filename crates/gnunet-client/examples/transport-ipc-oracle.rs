//! Real std socket/byte observer for the production current TRANSPORT codecs.
#![expect(
    clippy::print_stdout,
    reason = "The observer retains actual protocol observations"
)]
use gnunet_client::transport::{PeerId, Request, Response, Start};
use std::error::Error;

const PEER: PeerId = PeerId([0x11; 32]);
const MESSAGE: [u8; 8] = [0, 8, 0, 0, 0, 0, 0, 1];

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
    let mut buffer = [0; 128];
    let mut rows = Vec::new();
    for (name, request) in [
        ("start", Request::Start(Start::new(None, true))),
        (
            "send",
            Request::Send {
                peer: PEER,
                priority: 0,
                message: &MESSAGE,
            },
        ),
        (
            "recv_ok",
            Request::ReceiveContinue {
                peer: PEER,
                increase: 1,
            },
        ),
    ] {
        let len = request.encode(&mut buffer)?;
        if Request::decode(&buffer[..len])? != request {
            return Err("request round trip".into());
        }
        rows.push(format!("\"{name}\":\"{}\"", hex(&buffer[..len])));
    }
    for (name, response) in [
        ("connect", Response::Connected(PEER)),
        ("disconnect", Response::Disconnected(PEER)),
        ("send_ok", Response::SendCredit(PEER)),
        (
            "recv",
            Response::Received {
                peer: PEER,
                message: &MESSAGE,
            },
        ),
    ] {
        let len = response.encode(&mut buffer)?;
        if Response::decode(&buffer[..len])? != response {
            return Err("response round trip".into());
        }
        rows.push(format!("\"{name}\":\"{}\"", hex(&buffer[..len])));
    }
    println!("{{{}}}", rows.join(","));
    Ok(())
}
fn decode(text: &str) -> Result<(), Box<dyn Error>> {
    let bytes = unhex(text)?;
    let mut buffer = vec![0; 65535];
    let (direction, len) = match Request::decode(&bytes) {
        Ok(request) => ("request", request.encode(&mut buffer)?),
        Err(gnunet_types::Error::Unsupported) => {
            ("response", Response::decode(&bytes)?.encode(&mut buffer)?)
        }
        Err(error) => return Err(error.into()),
    };
    println!(
        "{{\"direction\":\"{direction}\",\"reencoded\":\"{}\"}}",
        hex(&buffer[..len])
    );
    Ok(())
}
#[cfg(unix)]
#[path = "transport-ipc-oracle/unix.rs"]
mod unix;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("vectors"), None) => vectors(),
        (Some("decode"), Some(bytes)) => decode(bytes),
        #[cfg(unix)]
        (Some(mode), Some(path)) => unix::run(mode, std::path::Path::new(path)),
        #[cfg(not(unix))]
        (Some(_), Some(_)) => Err("socket observation requires Unix sockets".into()),
        _ => Err("vectors | decode HEX | serve UNIXPATH | probe UNIXPATH".into()),
    }
}
