//! Rust TRANSPORT/public-PEERSTORE foreground with explicit PILS signing modes.
#![deny(unsafe_code)]
use gnunet_service_startup::{InheritedMode, InheritedResources};
use gnunet_transport_runtime::{
    Limits, LocalKeyCapability,
    startup::{self, LocalStartup, ServiceStartup},
};
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    task::Poll,
};
fn run() -> Result<(), Box<dyn Error>> {
    #[expect(
        unsafe_code,
        reason = "Early capture exclusively transfers inherited descriptors before runtime initialization"
    )]
    // SAFETY: first initialization operation, owning parent-transferred descriptors.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(a) => a,
        InheritedResources::CloseAfterBind(_) => {
            return Err("wrong foreground startup route".into());
        }
    };
    let parent_control = captured.parent_control;
    let mut selected = None;
    let mut directory = None;
    let mut local_key = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            writeln!(
                io::stdout().lock(),
                "Rust TRANSPORT + public PEERSTORE node: -c official.conf --state-directory NEW_RUST_STATE [--local-pils-key]; asynchronous PILS signing by default, optional verified local-key capability; SIGINT/SIGTERM shutdown"
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
            let interrupt_kind = tokio::signal::unix::SignalKind::interrupt();
            let terminate_kind = tokio::signal::unix::SignalKind::terminate();
            let mut interrupt = tokio::signal::unix::signal(interrupt_kind)?;
            let mut terminate = tokio::signal::unix::signal(terminate_kind)?;
            let mut control = parent_control
                .map(|p| p.register().map_err(|e| e.error))
                .transpose()?;
            let shutdown = std::future::poll_fn(|cx| {
                if let Some(pipe) = &mut control {
                    match pipe.poll_signal(cx) {
                        Poll::Ready(Ok(Some(signal)))
                            if i32::from(signal) == interrupt_kind.as_raw_value()
                                || i32::from(signal) == terminate_kind.as_raw_value() =>
                        {
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                        Poll::Ready(Ok(None)) => control = None,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {}
                    }
                }
                if interrupt.poll_recv(cx).is_ready() || terminate.poll_recv(cx).is_ready() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            });
            let ready = |_: &_, _: &_, peer: [u8; 32]| {
                let key: String = peer.iter().map(|b| format!("{b:02x}")).collect();
                let mut out = io::stdout().lock();
                writeln!(out, "READY {key}")?;
                out.flush()
            };
            let observe_socket = |event| {
                let _diagnostic = writeln!(io::stderr().lock(), "node socket: {event:?}");
            };
            let report = if let Some(ikm_file) = ikm_file {
                startup::foreground_local(
                    LocalStartup {
                        config: &config,
                        activation,
                        state_directory,
                        local_key: LocalKeyCapability { ikm_file },
                        limits: Limits::default(),
                    },
                    ready,
                    shutdown,
                    observe_socket,
                    startup::diagnose_pils,
                )
                .await?
            } else {
                startup::foreground_service(
                    ServiceStartup {
                        config: &config,
                        activation,
                        state_directory,
                        limits: Limits::default(),
                    },
                    ready,
                    shutdown,
                    observe_socket,
                    startup::diagnose_pils,
                )
                .await?
            };
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
