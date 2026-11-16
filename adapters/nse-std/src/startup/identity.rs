//! Read-only configured-account verification, independent of service work.
use gnunet_config::Configuration;
#[cfg(unix)]
use gnunet_service_startup::{Identity as ProcessIdentity, configured_user, resolve_user};
use std::error::Error;
/// Current process does not have the selected native account's actual primary
/// IDs. This is not a supplementary/saved-ID or capability guarantee.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfiguredIdentityMismatch {
    /// Actual UID selected by native account lookup.
    pub expected_uid: u32,
    /// Actual primary GID selected by native account lookup.
    pub expected_gid: u32,
    /// Actual current real/effective process IDs.
    pub actual: ProcessIdentity,
}
#[cfg(unix)]
impl std::fmt::Display for ConfiguredIdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NSE USERNAME requires uid={} gid={} before deferred Unix/proof/native service initialization; actual={:?}",
            self.expected_uid, self.expected_gid, self.actual
        )
    }
}
#[cfg(unix)]
impl Error for ConfiguredIdentityMismatch {}
#[cfg(unix)]
pub(super) fn require_ids(
    uid: u32,
    gid: u32,
    actual: ProcessIdentity,
) -> Result<(), ConfiguredIdentityMismatch> {
    if actual.uid != uid || actual.euid != uid || actual.gid != gid || actual.egid != gid {
        return Err(ConfiguredIdentityMismatch {
            expected_uid: uid,
            expected_gid: gid,
            actual,
        });
    }
    Ok(())
}
/// Verify that the embedding caller already applied the configured account
/// before proof/workers/native service initialization. This read-only check never
/// changes process identity from an async host. The standard executable can
/// retain its original inherited/prebound TCP listeners before applying the
/// native sequence; new Unix paths and proof/native clients still follow this
/// actual real/effective UID/GID check. Refusal never invents a privilege report.
pub fn verify_configured_identity(config: &Configuration) -> Result<(), Box<dyn Error>> {
    #[cfg(windows)]
    gnunet_service_startup::verify_configured_identity(config, b"NSE")?;
    #[cfg(unix)]
    if let Some(name) = configured_user(config, b"NSE")? {
        let plan = resolve_user(&name)?;
        require_ids(plan.uid(), plan.gid(), ProcessIdentity::current())?;
    }
    Ok(())
}
