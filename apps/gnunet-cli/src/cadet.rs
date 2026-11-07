//! Streaming official CADET inspection over an explicit native endpoint.
use super::peer::{hexadecimal, parse as peer};
use gnunet::{
    cadet_host::{
        EndpointSource,
        inspect::{Inspector, Limits, Query, Step},
    },
    wire::cadet::Response,
};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

fn row(out: &mut impl Write, value: serde_json::Value) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    Ok(())
}

fn entry(out: &mut impl Write, response: Response<'_>) -> Result<(), Box<dyn Error>> {
    let value = match response {
        Response::PeerInfo {
            paths,
            tunnel,
            best_path_length,
            peer,
        } => serde_json::json!({
            "event":"cadet_peer", "peer_hex":hexadecimal(&peer), "paths":paths,
            "tunnel":tunnel,"best_path_length":best_path_length
        }),
        Response::TunnelInfo {
            channels,
            peer,
            connections,
            encryption_state,
            connection_state,
        } => serde_json::json!({
            "event":"cadet_tunnel","peer_hex":hexadecimal(&peer),"channels":channels,
            "connections":connections,"encryption_state":encryption_state,"connection_state":connection_state
        }),
        Response::PathInfo { offset, peers } => serde_json::json!({
            "event":"cadet_path","offset":offset,
            "peers_hex":peers.iter().map(|peer|hexadecimal(&peer)).collect::<Vec<_>>()
        }),
        _ => return Err("unexpected CADET inspection entry".into()),
    };
    row(out, value)
}

pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let action = args.first().map(OsString::as_os_str);
    if action.is_none() || action == Some(OsStr::new("--help")) {
        writeln!(out, "cadet peers <UNIXPATH> [timeout-ms]")?;
        writeln!(out, "cadet tunnels <UNIXPATH> [timeout-ms]")?;
        writeln!(out, "cadet paths <UNIXPATH> <PEER> [timeout-ms]")?;
        writeln!(
            out,
            "PEER accepts the official GNUnet identity or hex. Default timeout: 10000 ms."
        )?;
        return Ok(());
    }
    let query = match action {
        Some(value) if value == "peers" => Query::Peers,
        Some(value) if value == "tunnels" => Query::Tunnels,
        Some(value) if value == "paths" => {
            Query::Paths(peer(args.get(2).ok_or("missing peer identity")?)?)
        }
        _ => return Err("expected cadet peers|tunnels|paths; see cadet --help".into()),
    };
    let required = if matches!(query, Query::Paths(_)) {
        3
    } else {
        2
    };
    if !(required..=required + 1).contains(&args.len()) {
        return Err("invalid CADET inspection arguments; see cadet --help".into());
    }
    let socket = PathBuf::from(args.get(1).ok_or("missing explicit CADET UNIXPATH")?);
    let milliseconds = args
        .get(required)
        .map(|value| {
            value
                .to_str()
                .ok_or("timeout must be a number")?
                .parse::<u64>()
                .map_err(|_| "invalid timeout")
        })
        .transpose()?
        .unwrap_or(10_000);
    if milliseconds == 0 {
        return Err("timeout must be nonzero".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let deadline = tokio::time::Instant::now()
                .checked_add(Duration::from_millis(milliseconds))
                .ok_or("timeout is not representable")?;
            let mut inspector =
                Inspector::new(EndpointSource::unix(socket), query, Limits::default())?;
            loop {
                match inspector.drive(Some(deadline)).await? {
                    Step::Entry(received) => entry(out, received.response()?)?,
                    Step::Complete(_actual_end) => {
                        let report = inspector.report();
                        row(
                            out,
                            serde_json::json!({"event":"cadet_end","entries":report.entries,
                        "query_written":report.query_written}),
                        )?;
                        return Ok::<(), Box<dyn Error>>(());
                    }
                    Step::Interrupted { cause, report } => {
                        row(
                            out,
                            serde_json::json!({"event":"cadet_interrupted","entries":report.entries,
                        "query_written":report.query_written,"written_bytes":report.written_bytes,
                        "cause":cause.to_string()}),
                        )?;
                        return Err(Box::new(cause));
                    }
                    Step::Unavailable(cause) => return Err(Box::new(cause)),
                    Step::WaitDeadline => {
                        return Err(Box::new(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "CADET inspection deadline before END",
                        )));
                    }
                    Step::Closed => return Err("CADET inspector closed before END".into()),
                    Step::Connected
                    | Step::Queued
                    | Step::Written { .. }
                    | Step::Activity
                    | Step::Retry { .. } => {}
                }
            }
        })
}
