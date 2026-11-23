//! Foreground executable for the ordinary Rust GNUnet node composition.
use gnunet_node_host::{Exit, Ready};
use gnunet_service_runtime::{clock::SystemClock, signals::Termination};
use std::{
    error::Error,
    future::poll_fn,
    io::{self, Write},
    net::SocketAddr,
    process::ExitCode,
    sync::Arc,
    task::{Context, Poll},
};

mod network;
mod options;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
mod systemd;
#[cfg(windows)]
mod windows_service;
use options::Options;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str = "Usage: gnunet-node --state-directory PATH --ipc-directory PATH \
[--config FILE] [--bootstrap-data-directory PATH] [--system-dns | [--dns-server ADDR]...] \
[--nat-helpers-directory PATH] \
[--startup-timeout-ms N] [--drain-timeout-ms N] \
(--outbound-tcp | (--tcp-bind ADDR | --tcp-dual-stack PORT) --udp4-bind ADDR [--udp6-bind ADDR])";

fn run() -> Result<()> {
    let mut argv = std::env::args_os().skip(1);
    let first = argv.next();
    match first.as_deref().and_then(std::ffi::OsStr::to_str) {
        #[cfg(any(
            all(target_os = "linux", not(target_env = "ohos")),
            target_os = "freebsd"
        ))]
        Some(gnunet_node_host::SYSTEM_DNS_WORKER_ARGUMENT) => {
            gnunet_node_host::serve_system_dns_worker(
                argv,
                io::stdin().lock(),
                io::stdout().lock(),
            )?;
            return Ok(());
        }
        #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
        Some("--systemd") => {
            let options = Options::parse(argv)?;
            let notify = systemd::Notify::from_environment()?;
            run_signalled(options, |_| notify.ready(), || notify.stopping())?;
            return Ok(());
        }
        #[cfg(windows)]
        Some("--windows-service") => return windows_service::dispatch(),
        Some("-h" | "--help" | "-V" | "--version") => {
            if argv.next().is_some() {
                return Err("help and version must be requested alone".into());
            }
            let mut output = io::stdout().lock();
            if matches!(
                first.as_deref().and_then(std::ffi::OsStr::to_str),
                Some("-h" | "--help")
            ) {
                writeln!(output, "{USAGE}")?;
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                writeln!(
                    output,
                    "  Linux storage check: [--require-storage-mount PATH]"
                )?;
                #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
                writeln!(
                    output,
                    "  Native service: place --systemd before the node options"
                )?;
                #[cfg(windows)]
                writeln!(
                    output,
                    "  Native service: place --windows-service before the node options"
                )?;
            } else {
                writeln!(output, "gnunet-node {}", env!("CARGO_PKG_VERSION"))?;
            }
            return Ok(());
        }
        _ => {}
    }
    let options = Options::parse(first.into_iter().chain(argv))?;
    let exit = run_signalled(options, write_ready, || Ok(()))?;
    let mut output = io::stdout().lock();
    match exit {
        Exit::BeforeReady => writeln!(output, "STOPPED before-ready")?,
        Exit::AfterReady(_) => writeln!(output, "STOPPED")?,
    }
    output.flush()?;
    Ok(())
}

fn reactor() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

fn run_signalled(
    options: Options,
    on_ready: impl FnOnce(&Ready) -> io::Result<()>,
    on_stop: impl Fn() -> io::Result<()>,
) -> Result<Exit> {
    reactor()?.block_on(async {
        let mut signals = Termination::new()?;
        run_node(
            options,
            |cx| match signals.poll_stop(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(on_stop()),
                result => result,
            },
            on_ready,
        )
        .await
    })
}

async fn run_node(
    options: Options,
    mut poll_stop: impl FnMut(&mut Context<'_>) -> Poll<io::Result<()>>,
    on_ready: impl FnOnce(&Ready) -> io::Result<()>,
) -> Result<Exit> {
    let node = options.prepare()?;
    let (mut network, changes) = network::Watch::start()?;
    let result = node
        .run(
            Arc::new(SystemClock),
            changes,
            poll_fn(|cx| {
                let stop = poll_stop(cx);
                if stop.is_pending()
                    && let Err(error) = network.poll(cx)
                {
                    return Poll::Ready(Err(error));
                }
                stop
            }),
            on_ready,
        )
        .await;
    let retired = network.close();
    match result {
        Ok(exit) => {
            retired?;
            Ok(exit)
        }
        Err(error) => {
            if let Err(cleanup) = retired {
                let _reported = writeln!(
                    io::stderr().lock(),
                    "gnunet-node: route notification cleanup failed: {cleanup}"
                );
            }
            Err(error.into())
        }
    }
}

fn write_ready(ready: &Ready) -> io::Result<()> {
    let mut output = io::stdout().lock();
    write!(output, "READY ")?;
    for byte in ready.peer {
        write!(output, "{byte:02x}")?;
    }
    write_endpoints(&mut output, "tcp", &ready.tcp_addresses)?;
    write_endpoints(&mut output, "udp", &ready.udp_addresses)?;
    if let Some(address) = ready.quic_address {
        write!(output, " quic={address}")?;
    }
    if let Some(address) = ready.http3_address {
        write!(output, " http3={address}")?;
    }
    if let Some(mtu) = ready.unix_mtu {
        write!(output, " unix_mtu={mtu}")?;
    }
    writeln!(output)?;
    output.flush()
}

fn write_endpoints(
    output: &mut impl Write,
    owner: &str,
    endpoints: &[SocketAddr],
) -> io::Result<()> {
    write!(output, " {owner}=")?;
    if let Some((first, others)) = endpoints.split_first() {
        write!(output, "{first}")?;
        for address in others {
            write!(output, ",{address}")?;
        }
    } else {
        write!(output, "none")?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-node: {error}");
            ExitCode::FAILURE
        }
    }
}
