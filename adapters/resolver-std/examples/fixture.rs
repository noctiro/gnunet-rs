//! Explicit isolated process fixture, not production configuration extensions.
use gnunet_resolver_host::{MachineFiles, startup};
use std::{
    error::Error,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};
fn main() -> Result<(), Box<dyn Error>> {
    let mut a = std::env::args_os().skip(1);
    let config = PathBuf::from(a.next().ok_or("config")?);
    let hosts = PathBuf::from(a.next().ok_or("hosts")?);
    let resolv = PathBuf::from(a.next().ok_or("resolv")?);
    let endpoint: SocketAddr = a
        .next()
        .ok_or("DNS endpoint")?
        .into_string()
        .map_err(|_| "DNS endpoint UTF8")?
        .parse()?;
    let ready = PathBuf::from(a.next().ok_or("ready")?);
    let stop = PathBuf::from(a.next().ok_or("stop")?);
    if a.next().is_some() {
        return Err("extra fixture argument".into());
    }
    let cfg = startup::configuration(Some(&config))?;
    let files = MachineFiles {
        hosts: std::fs::read(hosts)?,
        resolv: std::fs::read(resolv)?,
        diagnostics: Vec::new(),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let shutdown = async {
                loop {
                    if stop.is_file() {
                        return Ok::<_, io::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            let report = startup::foreground(
                &cfg,
                gnunet_service_runtime::Activation::default(),
                files,
                &[endpoint],
                |_| std::fs::write(&ready, b"ready\n"),
                shutdown,
                |event| {
                    if matches!(&event, gnunet_resolver_host::SocketEvent::Failed(error @ gnunet_resolver_host::AcceptError::Accept(_)) if error.is_emfile()) { return; }
                    let _diagnostic = writeln!(io::stderr().lock(), "resolver socket: {event:?}");
                },
            )
            .await?;
            writeln!(io::stdout().lock(), "{report:?}")?;
            Ok::<_, Box<dyn Error>>(())
        })
}
