//! Native-profile codec trace, no host service or network activity.
use gnunet_arm_core::wire::*;
use gnunet_types::Error;
use std::io::{self, Write};
fn frame(label: &str, bytes: &[u8], out: &mut impl Write) -> io::Result<()> {
    write!(
        out,
        "{{\"kind\":\"frame\",\"label\":\"{label}\",\"size\":{},\"hex\":\"",
        bytes.len()
    )?;
    for b in bytes {
        write!(out, "{b:02x}")?;
    }
    writeln!(out, "\"}}")
}
fn run(out: &mut impl Write) -> Result<(), Error> {
    let abi = ArmAbi::U64Align8;
    let id = WireId(0x0102030405060708);
    let mut bytes = [0u8; 128];
    for (label, r) in [
        (
            "START",
            Request::Start {
                reserved: 0,
                id,
                service: b"svc",
            },
        ),
        (
            "STOP",
            Request::Stop {
                reserved: 0,
                id,
                service: b"svc",
            },
        ),
        ("LIST", Request::List { reserved: 0, id }),
        ("MONITOR", Request::Monitor),
        ("TEST", Request::Test),
    ] {
        let n = r.encode(&mut bytes)?;
        frame(label, &bytes[..n], out).map_err(|_| Error::Io)?;
    }
    let n = ResultReply {
        reserved: 0,
        id,
        result: ResultCode(0x10111213),
    }
    .encode(abi, &mut bytes)?;
    frame("RESULT", &bytes[..n], out).map_err(|_| Error::Io)?;
    let n = Status {
        status: MonitorStatus(0x10111213),
        service: b"arm",
    }
    .encode(&mut bytes)?;
    frame("STATUS", &bytes[..n], out).map_err(|_| Error::Io)?;
    let rows = [ServiceInfo {
        name: b"svc",
        binary: b"bn",
        status: ServiceStatus::FAILED,
        last_exit_status: 65535,
        restart_at: 9,
        last_started_at: 10,
    }];
    let n = encode_list(abi, id, &rows, &mut bytes)?;
    frame("LIST_RESULT", &bytes[..n], out).map_err(|_| Error::Io)?;
    Ok(())
}
fn main() -> io::Result<()> {
    run(&mut io::stdout().lock()).map_err(io::Error::other)
}
