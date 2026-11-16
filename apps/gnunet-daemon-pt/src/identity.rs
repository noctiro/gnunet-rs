//! Native process identity before runtime or provider construction.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_program_host::reporting::Reporter;

pub(super) fn apply(config: &Configuration, reports: &Reporter) -> Result<(), Failure> {
    #[cfg(unix)]
    {
        use gnunet_service_startup::{
            GroupsProfile, apply_privileges, configured_user, resolve_user,
        };
        let user = configured_user(config, b"pt")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let actual = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.debug(
                "pt.process.identity",
                format_args!("PT process identity: {actual:?}"),
            );
        }
    }
    #[cfg(windows)]
    {
        let actual = gnunet_service_startup::verify_configured_identity(config, b"pt")?;
        reports.debug(
            "pt.process.identity",
            format_args!("PT process identity: {actual:?}"),
        );
    }
    Ok(())
}
