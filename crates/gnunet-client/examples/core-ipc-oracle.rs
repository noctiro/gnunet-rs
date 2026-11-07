//! Actual std socket/byte observer using production CORE application IPC owners.
#![expect(
    clippy::print_stdout,
    reason = "The observer records actual protocol output"
)]
use gnunet_client::core::{
    ClassOrder, Direction, KxState, MessageTypes, PeerClass, PeerId, Request, Response, Traffic,
};
use gnunet_wire::official::{MessageHeader, message_type};
use std::error::Error;

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
#[cfg(unix)]
#[path = "core-ipc-oracle/unix.rs"]
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
