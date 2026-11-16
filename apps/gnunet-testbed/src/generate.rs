//! One native batch owns its logical pool, root, publication and keep result.
use crate::Failure;
use gnunet_service_startup::{ParentControl, StopSignals};
use gnunet_testbed_host::{self as host, core};
use std::{
    error::Error,
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    task::Poll,
};
pub(super) struct Batch {
    pub count: usize,
    pub total_ports: usize,
    pub basename: OsString,
    pub output: PathBuf,
    pub configuration: gnunet_config::Configuration,
    pub options: host::Options,
    pub parent: Option<ParentControl>,
}
pub(super) fn run(batch: Batch) -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(execute(batch))
}
async fn execute(batch: Batch) -> Result<(), Failure> {
    let Batch {
        count,
        total_ports,
        basename,
        output,
        configuration,
        options,
        parent,
    } = batch;
    let mut control = StopSignals::for_client(parent)?;
    checkpoint(&mut control).await?;
    let mut slots = Vec::new();
    slots.try_reserve_exact(total_ports.max(1))?;
    slots.resize_with(total_ports.max(1), core::PortSlot::empty);
    let instance = core::Instance::new();
    let mut system = host::System::create(&instance, &mut slots, options)?;
    let mut stdout = io::stdout();
    let outcome = async {
        writeln!(stdout, "TESTBED root={} configurations={count} port-proof=bind-observation-only peer-ready=unclaimed", system.directory().display())?;
        for number in 0..count {
            checkpoint(&mut control).await?;
            let generated = system.configuration_create(&configuration)?;
            checkpoint(&mut control).await?;
            // Every exported config refers to this actual canonical publication.
            let canonical = system.write_configuration(&generated, &generated.default_config(), host::Replace::NewOnly)?;
            writeln!(stdout, "CANONICAL number={number} path={} bytes={} file-sync=completed directory-sync={:?}", canonical.path().display(), canonical.bytes(), canonical.directory_sync())?;
            checkpoint(&mut control).await?;
            let mut name = OsString::from(format!("{number:04}-"));
            name.push(&basename);
            let published = system.write_configuration(&generated, &output.join(name), host::Replace::Allowed)?;
            writeln!(stdout, "CONFIG number={number} path={} bytes={} logical-ports={} file-sync=completed directory-sync={:?} service-ready=unclaimed", published.path().display(), published.bytes(), generated.ports().count(), published.directory_sync())?;
        }
        stdout.flush()?;
        checkpoint(&mut control).await
    }.await;
    let cleanup = system.destroy(false);
    match (outcome, cleanup) {
        (Ok(()), Ok(kept)) => {
            writeln!(stdout, "STOPPED paths={kept:?} processes-started=0")?;
            Ok(())
        }
        (Err(original), Ok(_)) => Err(original),
        (Ok(()), Err(error)) => Err(error.into()),
        (Err(original), Err(cleanup)) => Err(Box::new(CleanupFailure { original, cleanup })),
    }
}
async fn checkpoint(control: &mut StopSignals) -> Result<(), Failure> {
    tokio::task::yield_now().await;
    std::future::poll_fn(|cx| {
        Poll::Ready(match control.poll_stop(cx) {
            Poll::Pending => Ok(()),
            Poll::Ready(Err(error)) => Err(Box::new(error) as Failure),
            Poll::Ready(Ok(())) => {
                Err(io::Error::new(io::ErrorKind::Interrupted, "TESTBED generation stopped").into())
            }
        })
    })
    .await
}
#[derive(Debug)]
struct CleanupFailure {
    original: Failure,
    cleanup: host::Failure,
}
impl std::fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; independent TESTBED cleanup failure: {}",
            self.original, self.cleanup
        )
    }
}
impl Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
