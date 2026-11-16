//! Independent original native, protocol and cleanup causes.
use crate::{Cause, state::Report};
use gnunet_cadet_host as cadet;
use gnunet_resolver_broker::BrokerError;
use gnunet_service_startup::StopError;
use std::{error::Error, fmt, io};

#[derive(Debug, Default)]
pub(super) struct Errors {
    pub(super) original: [Option<Cause>; 4],
    pub(super) additional_original: u64,
    pub(super) loss: Option<cadet::LossCause>,
    pub(super) native: Option<cadet::Error>,
    pub(super) input: Option<io::Error>,
    pub(super) signal: Option<StopError>,
    pub(super) output: Option<io::Error>,
    pub(super) close: Option<cadet::Error>,
    pub(super) stdio: Option<crate::stdio::Retired>,
    pub(super) resolver: Option<BrokerError>,
    pub(super) resolver_close: Option<BrokerError>,
    pub(super) logging: Option<io::Error>,
}
impl Errors {
    pub(super) fn record(&mut self, error: Cause) {
        if let Some(slot) = self.original.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            self.additional_original = self.additional_original.saturating_add(1);
        }
    }
    pub(super) fn failed(&self) -> bool {
        self.original.iter().any(Option::is_some)
            || self.additional_original != 0
            || self.loss.is_some()
            || self.native.is_some()
            || self.input.is_some()
            || self.signal.is_some()
            || self.output.is_some()
            || self.close.is_some()
            || self.stdio.is_some()
            || self.resolver.is_some()
            || self.resolver_close.is_some()
            || self.logging.is_some()
    }
}
#[derive(Debug)]
pub(super) struct Failed {
    pub(super) report: Report,
    pub(super) errors: Errors,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CADET stream terminal facts: {:?}; causes: {:?}",
            self.report, self.errors
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors
            .original
            .iter()
            .find_map(|error| error.as_deref())
            .or(match self.errors.loss.as_ref() {
                Some(cadet::LossCause::Io(error)) => Some(error as &dyn Error),
                Some(cadet::LossCause::Protocol(error)) => Some(error as &dyn Error),
                _ => None,
            })
            .or_else(|| self.errors.native.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.input.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.signal.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.output.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.close.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.stdio.as_ref().map(|error| error as &dyn Error))
            .or_else(|| {
                self.errors
                    .resolver
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .resolver_close
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .logging
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
    }
}
