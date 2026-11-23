//! Rust TRANSPORT/public-PEERSTORE foreground with explicit PILS signing modes.
#![deny(unsafe_code)]
use gnunet_service_runtime::BoundListeners;
use gnunet_transport_runtime::{
    Limits, LocalKeyCapability,
    startup::{self, LocalStartup, ServiceStartup},
};
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod bootstrap;
fn run() -> Result<(), Failure> {
    #[expect(
        unsafe_code,
        reason = "Early capture exclusively transfers inherited descriptors before runtime initialization"
    )]
    // SAFETY: first initialization operation, owning parent-transferred descriptors.
    let (activation, parent_control) = unsafe { bootstrap::capture()? };
    let mut selected = None;
    let mut directory = None;
    let mut local_key = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            writeln!(
                io::stdout().lock(),
                "Rust TRANSPORT + public PEERSTORE node: -c official.conf --state-directory NEW_RUST_STATE [--local-pils-key]; asynchronous PILS signing by default, optional verified local-key capability; native or parent-control shutdown"
            )?;
            return Ok(());
        }
        if arg == "--version" || arg == "-v" {
            writeln!(
                io::stdout().lock(),
                "gnunet-transport-node Rust / official v0.29.1"
            )?;
            return Ok(());
        }
        if arg == "-c" || arg == "--config" {
            if selected.is_some() {
                return Err("duplicate config".into());
            }
            selected = Some(PathBuf::from(args.next().ok_or("missing config")?));
        } else if arg == "--state-directory" {
            if directory.is_some() {
                return Err("duplicate state directory".into());
            }
            directory = Some(PathBuf::from(
                args.next().ok_or("missing new-format state directory")?,
            ));
        } else if arg == "--local-pils-key" {
            if local_key {
                return Err("duplicate local capability".into());
            }
            local_key = true;
        } else {
            return Err("unsupported foreground option; see --help".into());
        }
    }
    let state_directory =
        directory.ok_or("explicit --state-directory for new-format Rust backend is required")?;
    let config = startup::configuration(selected.as_deref())?;
    let included_hellos = startup::IncludedHellos::configured(&config)?;
    let ikm_file = if local_key {
        Some(config.get_filename(
            b"peer",
            b"PRIVATE_KEY",
            &gnunet_transport_runtime::startup::ProcessEnvironment,
        )?)
    } else {
        None
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let bootstrap::Registered {
                control,
                #[cfg(windows)]
                mut ready,
            } = bootstrap::register(parent_control)?;
            let result = async {
                let mut signals = gnunet_service_startup::StopSignals::new(control)?;
                let shutdown = std::future::poll_fn(|cx| {
                    signals
                        .poll_stop(cx)
                        .map(|result| result.map_err(io::Error::other))
                });
                let activated = async |_: &BoundListeners, _: &BoundListeners, peer: [u8; 32]| {
                    {
                        let mut out = io::stdout().lock();
                        write!(out, "READY ")?;
                        for byte in peer {
                            write!(out, "{byte:02x}")?;
                        }
                        writeln!(out)?;
                        out.flush()?;
                    }
                    #[cfg(windows)]
                    if let Some(writer) = &mut ready {
                        tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            writer.signal(gnunet_service_startup::ReadyStatus::AcceptRegistered),
                        )
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "node readiness deadline")
                        })?
                        .map_err(io::Error::other)?;
                        drop(ready.take());
                    }
                    Ok(())
                };
                let observe_socket = |event| {
                    let _diagnostic = writeln!(io::stderr().lock(), "node socket: {event:?}");
                };
                if let Some(ikm_file) = ikm_file {
                    startup::foreground_local(
                        LocalStartup {
                            config: &config,
                            activation,
                            state_directory,
                            included_hellos,
                            local_key: LocalKeyCapability { ikm_file },
                            limits: Limits::default(),
                        },
                        activated,
                        shutdown,
                        observe_socket,
                        startup::diagnose_pils,
                    )
                    .await
                } else {
                    startup::foreground_service(
                        ServiceStartup {
                            config: &config,
                            activation,
                            state_directory,
                            included_hellos,
                            limits: Limits::default(),
                        },
                        activated,
                        shutdown,
                        observe_socket,
                        startup::diagnose_pils,
                    )
                    .await
                }
            }
            .await;
            #[cfg(windows)]
            let result = bootstrap::finish(result, &mut ready).await;
            let report = result?;
            writeln!(io::stdout().lock(), "STOPPED {report:?}")?;
            Ok::<_, Box<dyn Error>>(())
        })
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-transport-node: {error}");
            ExitCode::FAILURE
        }
    }
}
