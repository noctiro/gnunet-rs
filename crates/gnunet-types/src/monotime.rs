//! Allocation-free issuance of signed time from a durable high-water mark.

use crate::{AbsoluteTime, Error};
use core::num::NonZeroU64;

/// Original issuance or durable reservation failure.
#[derive(Debug, Eq, PartialEq)]
pub enum IssueError<E> {
    /// The window is closed, exhausted or received an invalid range.
    Sequence(Error),
    /// The persistence provider could not confirm the original reservation.
    Reserve(E),
}

/// Exclusive signed timestamp issuer for an original durable namespace.
/// Unused portions of a persisted range are burned when the owner is restored.
/// Logical time may regress independently of this strictly increasing sequence.
pub struct Window {
    state: Option<Range>,
}

struct Range {
    used: u64,
    reserved: u64,
}

impl Window {
    /// Begin under exclusive ownership of the original state after loading its
    /// authoritative durable high-water mark. Zero represents a fresh namespace.
    ///
    /// # Errors
    /// The forever sentinel is not a valid persisted timestamp.
    pub const fn resume(high_water: u64) -> Result<Self, Error> {
        if high_water == u64::MAX {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            state: Some(Range {
                used: high_water,
                reserved: high_water,
            }),
        })
    }

    /// Issue one signed time. `reserve` must exclusively commit an inclusive
    /// range in the original durable namespace before returning it. Its first
    /// value must be at least the requested value. A reservation provider owns
    /// the storage barrier and namespace fencing, including during cached use.
    ///
    /// # Errors
    /// Exhaustion, an unconfirmed commit or an invalid returned range closes
    /// this window. Resumption requires recovering the authoritative mark.
    pub fn issue<E>(
        &mut self,
        observed: AbsoluteTime,
        reserve: impl FnOnce(NonZeroU64) -> Result<(u64, u64), E>,
    ) -> Result<NonZeroU64, IssueError<E>> {
        let mut range = self
            .state
            .take()
            .ok_or(IssueError::Sequence(Error::Closed))?;
        let next = range
            .used
            .checked_add(1)
            .ok_or(IssueError::Sequence(Error::Overflow))?;
        let wanted = next.max(observed.as_micros());
        let wanted = NonZeroU64::new(wanted)
            .filter(|wanted| wanted.get() != u64::MAX)
            .ok_or(IssueError::Sequence(Error::Overflow))?;
        let (issued, reserved) = if wanted.get() > range.reserved {
            reserve(wanted).map_err(IssueError::Reserve)?
        } else {
            (wanted.get(), range.reserved)
        };
        if issued < wanted.get() || reserved < issued || reserved == u64::MAX {
            return Err(IssueError::Sequence(Error::Conflict));
        }
        let issued = NonZeroU64::new(issued).ok_or(IssueError::Sequence(Error::Conflict))?;
        range.used = issued.get();
        range.reserved = reserved;
        self.state = Some(range);
        Ok(issued)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert values after checked issuance"
    )]
    fn restart_burns_unissued_time_and_wall_rollback_keeps_order() -> Result<(), IssueError<Error>>
    {
        let mut before = Window::resume(0).map_err(IssueError::Sequence)?;
        let first = before.issue(AbsoluteTime::from_micros(50), |min| Ok((min.get(), 59)))?;
        let second = before.issue(AbsoluteTime::UNIX_EPOCH, |_| Err(Error::Conflict))?;
        assert_eq!((first.get(), second.get()), (50, 51));

        let mut restored = Window::resume(59).map_err(IssueError::Sequence)?;
        let resumed = restored.issue(AbsoluteTime::UNIX_EPOCH, |min| Ok((min.get(), 69)))?;
        assert_eq!(resumed.get(), 60);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert terminal issuance results"
    )]
    fn failed_or_invalid_reservation_fences_issuance() -> Result<(), Error> {
        let mut failed = Window::resume(5)?;
        let observed = AbsoluteTime::from_micros(20);
        assert_eq!(
            failed.issue(observed, |_| Err(Error::OutcomeUnknown)),
            Err(IssueError::Reserve(Error::OutcomeUnknown))
        );
        assert_eq!(
            failed.issue(observed, |_| Ok::<_, Error>((21, 22))),
            Err(IssueError::Sequence(Error::Closed))
        );

        let mut invalid = Window::resume(5)?;
        assert_eq!(
            invalid.issue(observed, |_| Ok::<_, Error>((19, 22))),
            Err(IssueError::Sequence(Error::Conflict))
        );
        assert_eq!(
            invalid.issue(observed, |_| Ok::<_, Error>((21, 22))),
            Err(IssueError::Sequence(Error::Closed))
        );
        Ok(())
    }
}
