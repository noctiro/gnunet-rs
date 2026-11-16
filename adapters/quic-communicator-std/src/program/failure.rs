//! Independent native, Resolver, control and diagnostic causes.
use super::Failure;
use gnunet_service_startup::StopError;
use std::{error::Error, io};
#[derive(Debug, Default)]
pub(super) struct Failures {
    pub(super) original: Option<Failure>,
    pub(super) signal: Option<StopError>,
    pub(super) resolver: Option<Failure>,
    pub(super) disconnect: Option<Failure>,
    pub(super) cleanup: Option<crate::Fault>,
    pub(super) diagnostic: Option<io::Error>,
}
impl Failures {
    pub(super) fn finish(self) -> Result<(), Failure> {
        if self.original.is_none()
            && self.signal.is_none()
            && self.resolver.is_none()
            && self.disconnect.is_none()
            && self.cleanup.is_none()
            && self.diagnostic.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("communicator failures")?;
        for (name, error) in [
            ("original", self.original.as_deref()),
            ("resolver", self.resolver.as_deref()),
            ("resolver-close", self.disconnect.as_deref()),
        ] {
            if let Some(e) = error {
                write!(f, "; {name}: {e}")?
            }
        }
        if let Some(e) = &self.signal {
            write!(f, "; signal: {e}")?
        }
        if let Some(e) = &self.cleanup {
            write!(f, "; native cleanup: {e}")?
        }
        if let Some(e) = &self.diagnostic {
            write!(f, "; diagnostic: {e}")?
        }
        Ok(())
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.signal.as_ref().map(|error| error as _))
            .or(self.resolver.as_deref())
            .or(self.disconnect.as_deref())
            .or(self.cleanup.as_ref().map(|error| error as _))
            .or(self.diagnostic.as_ref().map(|error| error as _))
    }
}
