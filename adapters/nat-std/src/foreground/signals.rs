//! Original native stop and consuming parent readiness, without another task.
use crate::manager::Failure;
use gnunet_program_host::reporting::Reporter;
use gnunet_service_startup::{ParentControl, StopSignals};
use std::time::Duration;

pub(super) struct Signals {
    pub stop: StopSignals,
    #[cfg(windows)]
    ready: Option<gnunet_service_startup::ReadyWriter>,
}
impl Signals {
    pub fn new(parent: Option<ParentControl>) -> Result<Self, Failure> {
        #[cfg(unix)]
        let parent = parent
            .map(|parent| parent.register().map_err(|error| error.error))
            .transpose()?;
        #[cfg(windows)]
        let (parent, ready) = match parent.map(|parent| parent.register()).transpose()? {
            Some(parent) => (Some(parent.control), Some(parent.ready)),
            None => (None, None),
        };
        Ok(Self {
            stop: StopSignals::new(parent)?,
            #[cfg(windows)]
            ready,
        })
    }
    pub async fn ready(&mut self, reports: &Reporter) -> Result<(), Failure> {
        let notification = async {
            #[cfg(windows)]
            if let Some(writer) = &mut self.ready {
                writer
                    .signal(gnunet_service_startup::ReadyStatus::AcceptRegistered)
                    .await?;
            }
            Ok::<_, Failure>(())
        };
        gnunet_program_host::service::acknowledge_ready(
            notification,
            &mut self.stop,
            reports,
            Duration::from_secs(5),
        )
        .await?;
        #[cfg(windows)]
        drop(self.ready.take());
        Ok(())
    }
}
