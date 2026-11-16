//! Process identity setup after numeric binds and before private state/workers.
use crate::Cause;
#[cfg(unix)]
pub(super) fn apply(config: &gnunet_config::Configuration) -> Result<(), Cause> {
    use gnunet_service_startup::{GroupsProfile, apply_privileges, configured_user, resolve_user};
    let user = configured_user(config, b"communicator-udp")?
        .map(|name| resolve_user(&name))
        .transpose()?;
    apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
    Ok(())
}
#[cfg(windows)]
pub(super) fn apply(config: &gnunet_config::Configuration) -> Result<(), Cause> {
    gnunet_service_startup::verify_configured_identity(config, b"communicator-udp")?;
    Ok(())
}
