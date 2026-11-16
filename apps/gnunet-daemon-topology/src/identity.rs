//! Configured process identity before reactor and provider construction.
use crate::{Failure, reporting::Reports};
use gnunet_config::Configuration;
pub(super) fn apply(config: &Configuration, reports: &Reports) -> Result<(), Failure> {
    #[cfg(unix)]
    {
        use gnunet_service_startup::{
            GroupsProfile, apply_privileges, configured_user, resolve_user,
        };
        let user = configured_user(config, b"topology")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let applied = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.debug(
                "topology.process.identity",
                format_args!("Configured process identity: {applied:?}"),
            );
        }
    }
    #[cfg(windows)]
    {
        let identity = gnunet_service_startup::verify_configured_identity(config, b"topology")?;
        reports.debug(
            "topology.process.identity",
            format_args!("Verified process identity: {identity:?}"),
        );
    }
    Ok(())
}
