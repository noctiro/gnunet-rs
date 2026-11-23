//! macOS system-extension launch, bundle layout and main run-loop ownership.
use super::run_session;
use crate::Failure;
use gnunet_native::dns_proxy::provider::{self, Controller, ProviderLimits};
use std::io;

struct WorkerExit(provider::ShutdownHandle);
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.request_shutdown();
        provider::stop_run_loop();
    }
}

pub(crate) fn run() -> Result<(), Failure> {
    let executable = std::env::current_exe()?;
    let binaries = executable
        .parent()
        .ok_or("DNS provider binary directory is absent")?;
    let resources = binaries
        .parent()
        .ok_or("DNS provider bundle layout is invalid")?
        .join("Resources");
    let binaries = binaries.to_owned();
    let controller = Controller::register(ProviderLimits::default())?;
    let shutdown = controller.shutdown_handle();
    let worker_shutdown = shutdown.clone();
    let worker = std::thread::Builder::new()
        .name("gnunet-dns-provider".to_owned())
        .spawn(move || {
            let _exit = WorkerExit(worker_shutdown);
            run_session(controller, &resources, &binaries).map_err(|error| error.to_string())
        })?;
    let native = provider::run_system_extension();
    shutdown.request_shutdown();
    let owned = worker
        .join()
        .map_err(|_| io::Error::other("DNS provider worker panicked"))?;
    native?;
    owned.map_err(Into::into)
}
