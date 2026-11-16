//! Native identity boundary after binds and before key/frontier admission.
use crate::{Failure, stop_requested};
use gnunet_program_host::reporting::Reporter;
use std::{future::Future, io, pin::Pin};
pub(super) async fn apply<S: Future<Output = io::Result<()>> + ?Sized>(
    config: &gnunet_config::Configuration,
    shutdown: Pin<&mut S>,
    reporter: &Reporter,
) -> Result<bool, Failure> {
    #[cfg(unix)]
    {
        use gnunet_service_startup::{
            GroupsProfile, apply_privileges, configured_user, resolve_user,
        };
        let user = configured_user(config, b"communicator-tcp")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        if stop_requested(shutdown, reporter).await? {
            return Ok(false);
        }
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reporter.debug(
                "tcp.identity.applied",
                format_args!("TCP configured process identity: {privileges:?}"),
            );
        }
    }
    #[cfg(windows)]
    {
        gnunet_service_startup::verify_configured_identity(config, b"communicator-tcp")?;
        if stop_requested(shutdown, reporter).await? {
            return Ok(false);
        }
    }
    Ok(!reporter.failed())
}
