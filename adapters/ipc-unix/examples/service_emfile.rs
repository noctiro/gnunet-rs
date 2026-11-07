//! High-capacity STATISTICS component fixture for actual native EMFILE ownership.
#![forbid(unsafe_code)]
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_ipc_unix::server::{self, Listener, ServiceEvent, ServiceOptions};
use gnunet_service_runtime::accepted::SocketEvent;
use gnunet_statistics::Statistics;
use std::{
    error::Error,
    io::{self, Write},
    net::Ipv4Addr,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, UnixListener},
};
fn emit(value: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{value}")?;
    out.flush()
}
async fn run(cfg: Configuration) -> Result<(), Box<dyn Error>> {
    let path = cfg.get_filename(b"statistics", b"UNIXPATH", &ProcessEnvironment)?;
    let port = u16::try_from(cfg.get_number(b"statistics", b"PORT")?)?;
    let unix = UnixListener::bind(&path)?;
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    let mut core = Statistics::<1, 32, 1100, 0, 16>::new();
    let mut observation_failure = None;
    emit("READY")?;
    let report = server::serve_statistics_on(
        &[Listener::Unix(&unix), Listener::Tcp(&tcp)],
        &mut core,
        server::Limits {
            max_connections: 1100,
            max_frame_bytes: 64,
            max_pending_bytes: 64,
            idle_timeout: Duration::MAX,
        },
        &ServiceOptions::default(),
        async {
            let mut stdin = tokio::io::stdin();
            let mut byte = [0];
            let _result = stdin.read_exact(&mut byte).await;
        },
        |event| {
            let result = match event {
                ServiceEvent::ForcedShutdown => emit("FORCED_SHUTDOWN"),
                ServiceEvent::Socket(SocketEvent::Failed(error)) => emit(&format!(
                    "SOCKET_FAILED|{}|{}",
                    error.io_error().raw_os_error().unwrap_or(0),
                    error
                )),
                ServiceEvent::Socket(SocketEvent::Diagnostic(diagnostic)) => {
                    emit(&format!("SOCKET_DIAGNOSTIC|{diagnostic:?}"))
                }
                ServiceEvent::Closed(closed) => emit(&format!(
                    "CLOSED|{}|{:?}",
                    closed.client.is_some(),
                    closed.reason
                )),
            };
            if let Err(error) = result {
                observation_failure = Some(error);
            }
        },
    )
    .await?;
    if let Some(error) = observation_failure {
        return Err(error.into());
    }
    if core.client_count() != 0 {
        return Err(io::Error::other("fixture retained a client after real shutdown").into());
    }
    emit(&format!(
        "REPORT|{}|{}|{}|{}",
        report.accepted, report.admitted, report.rejected, report.closed
    ))?;
    drop(unix);
    drop(tcp);
    std::fs::remove_file(path)?;
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4
        || arguments[0] != "-c"
        || arguments[2] != "-L"
        || arguments[3] != "DEBUG"
    {
        return Err(io::Error::other("fixture requires -c OWNED-CONFIG -L DEBUG").into());
    }
    let mut cfg = Configuration::default();
    cfg.parse(std::path::Path::new(&arguments[1]))?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(cfg))
}
