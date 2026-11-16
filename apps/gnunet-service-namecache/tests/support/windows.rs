//! Original native child, qualified private bootstrap and cooperative control.
use super::{Directory, Failure, check};
use gnunet_native::process::{LaunchLimits, Stdio};
use gnunet_service_runtime::{
    Activation,
    process::{ChildRegistry, OriginalChild},
};
use gnunet_service_startup::daemon::{self, Reexec};
use std::{
    ffi::{OsStr, OsString},
    future::poll_fn,
    path::{Path, PathBuf},
    time::Duration,
};
pub struct Service {
    registry: ChildRegistry,
    child: Option<OriginalChild>,
    startup: Option<daemon::Parent>,
}
impl Service {
    pub fn new() -> Result<Self, Failure> {
        Ok(Self {
            registry: ChildRegistry::new(1)?,
            child: None,
            startup: None,
        })
    }
    pub async fn start(&mut self, directory: &Directory, config: &Path) -> Result<(), Failure> {
        let executable = PathBuf::from(env!("CARGO_BIN_EXE_gnunet-service-namecache"));
        let arguments = vec![OsString::from("-d"), OsString::from("-c"), config.into()];
        let parent = match daemon::launch(
            &mut self.registry,
            Reexec {
                executable: &executable,
                argv0: OsStr::new("gnunet-service-namecache"),
                arguments: &arguments,
                environment: directory.environment(),
                directory: &directory.0,
                stderr: Stdio::Inherit,
                activation: Activation::default(),
            },
            LaunchLimits::default(),
        ) {
            Ok(parent) => parent,
            Err(error) => {
                self.child = error.child.clone();
                return Err(Box::new(error));
            }
        };
        self.child = Some(parent.child().clone());
        self.startup = Some(parent);
        let parent = self.startup.as_mut().ok_or("missing original bootstrap")?;
        let receipt = parent.wait().await?;
        check(
            receipt.child() == parent.child(),
            "ready receipt changed original child",
        )?;
        Ok(())
    }
    pub async fn stop(&mut self) -> Result<(), Failure> {
        let parent = self.startup.as_mut().ok_or("missing original bootstrap")?;
        let mut control = parent
            .take_control()
            .ok_or("missing qualified parent control")?;
        control.begin(&self.registry, 15)?;
        poll_fn(|cx| control.poll_send(cx)).await?;
        let child = self
            .child
            .as_ref()
            .ok_or("missing original service child")?;
        let mut exit = self.registry.exit_observer(child)?;
        poll_fn(|cx| exit.poll_exit(cx)).await?;
        let reaped = self
            .registry
            .reap_child(child)?
            .ok_or("original exit not reaped")?;
        self.child = None;
        self.startup = None;
        check(reaped.exit_code == 0, "normal service shutdown failed")?;
        Ok(())
    }
    pub async fn retire(&mut self) -> Result<(), Failure> {
        if let Some(child) = &self.child {
            tokio::time::timeout(
                Duration::from_secs(5),
                daemon::retire_child(&mut self.registry, child, 1),
            )
            .await??;
            self.child = None;
            self.startup = None;
        }
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        if let Some(child) = &self.child {
            let _stop = self.registry.terminate(child, 1);
            let _reap = self.registry.reap_child(child);
        }
    }
}
