//! Local cancellation joins logical refusal with the same operation's actual
//! native quiescence. This owns bounded metadata, never a second native job.
use super::*;

/// Keep the first triggering error and first independent cleanup failure. A
/// cleanup error cannot stop later original owners from being visited.
#[derive(Default)]
pub(super) struct Errors {
    first: Option<Error>,
    cleanup: Option<Error>,
}
impl Errors {
    pub(super) fn record(&mut self, result: Result<(), Error>) {
        if let Err(error) = result {
            if self.first.is_none() {
                self.first = Some(error);
            } else if self.cleanup.is_none() {
                self.cleanup = Some(error);
            }
        }
    }
    pub(super) fn finish(self, cleanup: &mut Option<Error>) -> Result<(), Error> {
        if cleanup.is_none() {
            *cleanup = self.cleanup;
        }
        self.first.map_or(Ok(()), Err)
    }
}
pub(super) struct Retained {
    pub(super) errors: Errors,
    /// The caller must physically fence this original source before dropping
    /// its operation association. It does not settle external transport output.
    pub(super) fence: bool,
}

pub(super) fn retain<I: Copy + Eq>(
    pending: &mut Vec<Retiring<I>>,
    operation: I,
    original: Instant,
    grace: std::time::Duration,
    limit: usize,
    canceled: Result<(), Error>,
    quiescent: Result<bool, Error>,
) -> Retained {
    let mut errors = Errors::default();
    errors.record(canceled);
    let quiescent = match quiescent {
        Ok(value) => value,
        Err(error) => {
            errors.record(Err(error));
            return Retained {
                errors,
                fence: true,
            };
        }
    };
    if quiescent || pending.iter().any(|row| row.operation == operation) {
        return Retained {
            errors,
            fence: false,
        };
    }
    if pending.len() >= limit {
        errors.record(Err(Protocol::Capacity.into()));
        return Retained {
            errors,
            fence: true,
        };
    }
    let Some(hard) = original.min(Instant::now()).checked_add(grace) else {
        errors.record(Err(Protocol::Overflow.into()));
        return Retained {
            errors,
            fence: true,
        };
    };
    pending.push(Retiring { operation, hard });
    Retained {
        errors,
        fence: false,
    }
}

#[cfg(test)]
#[path = "cancellation/tests.rs"]
mod tests;
