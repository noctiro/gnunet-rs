//! Explicit failed-child retirement without consuming unrelated registry credit.
use gnunet_service_runtime::process::{ChildRegistry, OriginalChild, Reaped, RegistryError};
use std::{error::Error, fmt, io};

/// Original retirement refusal and any independent exit-query failure.
#[derive(Debug)]
pub struct RetirementFailure {
    /// First query, observer, termination or final reaping failure.
    pub original: RegistryError,
    /// Separate exit query failed while settling a refused termination request.
    pub observation: Option<RegistryError>,
}
impl fmt::Display for RetirementFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.original.fmt(f)?;
        if let Some(error) = &self.observation {
            write!(f, "; independent exit observation: {error}")?;
        }
        Ok(())
    }
}
impl Error for RetirementFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}
impl From<RegistryError> for RetirementFailure {
    fn from(original: RegistryError) -> Self {
        Self {
            original,
            observation: None,
        }
    }
}
impl From<io::Error> for RetirementFailure {
    fn from(error: io::Error) -> Self {
        RegistryError::from(error).into()
    }
}

/// Terminate and drain one exact original child, or consume its already observed
/// exit. The request code is a native process code, not a signal or exit receipt.
/// Other original children and untaken receipts remain in their registry.
/// Cancellation preserves the caller's registry/process authority; local wait
/// teardown never waits for child exit. Failed native operations remain errors.
pub async fn retire_child(
    registry: &mut ChildRegistry,
    child: &OriginalChild,
    exit_code: u32,
) -> Result<Reaped, RetirementFailure> {
    if let Some(receipt) = registry.reap_child(child)? {
        return Ok(receipt);
    }
    let mut observer = registry.exit_observer(child)?;
    if let Err(original) = registry.terminate(child, exit_code) {
        // Only physical exit can settle a race with the refused termination.
        return match registry.reap_child(child) {
            Ok(Some(receipt)) => Ok(receipt),
            Ok(None) => Err(original.into()),
            Err(observation) => Err(RetirementFailure {
                original,
                observation: Some(observation),
            }),
        };
    }
    std::future::poll_fn(|cx| observer.poll_exit(cx)).await?;
    registry
        .reap_child(child)?
        .ok_or_else(|| RegistryError::Stale.into())
}
