//! Windows startup validates primary-token identity without mutating credentials.
use gnunet_config::Configuration;
use gnunet_native::identity::{Sid, account_sid, process_user};
use std::{fmt, io};

/// Configuration, native account lookup or actual process identity refusal.
#[derive(Debug)]
pub enum IdentityError {
    /// Original present USERNAME expansion failure.
    Configuration(gnunet_config::Error),
    /// Original Win32 token/account query error.
    Native(io::Error),
    /// The requested account is different from the actual primary-token user.
    Mismatch(Box<IdentityMismatch>),
}
/// Two independently observed native identities at startup refusal.
#[derive(Debug)]
pub struct IdentityMismatch {
    /// SID resolved for the configured account.
    pub requested: Sid,
    /// SID observed from the running process's primary token.
    pub actual: Sid,
}
impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => error.fmt(f),
            Self::Native(error) => error.fmt(f),
            Self::Mismatch(mismatch) => write!(
                f,
                "configured USERNAME requires {}; process token user is {}",
                mismatch.requested, mismatch.actual
            ),
        }
    }
}
impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::Mismatch(_) => None,
        }
    }
}

/// Verify USERNAME against the actual Windows process-token SID and return that
/// immutable observation. Missing USERNAME preserves the current identity. A
/// different requested user fails before service startup; launching under another
/// account belongs to the process supervisor, never thread impersonation or a
/// synthetic Unix identity. This grants no file, group or peer access capability.
pub fn verify_configured_identity(
    config: &Configuration,
    section: &[u8],
) -> Result<Sid, IdentityError> {
    let actual = process_user().map_err(IdentityError::Native)?;
    if let Some(name) =
        crate::configured_user(config, section).map_err(IdentityError::Configuration)?
    {
        let requested = account_sid(&name).map_err(IdentityError::Native)?;
        if requested != actual {
            return Err(IdentityError::Mismatch(Box::new(IdentityMismatch {
                requested,
                actual,
            })));
        }
    }
    Ok(actual)
}
