//! One original handle admission and its immutable native close observation.
use std::io;

#[derive(Debug)]
pub(super) enum Handle {
    Open(usize),
    AttemptingClose,
    Attempted(Result<(), i32>),
}
impl Handle {
    pub fn original(&self) -> io::Result<usize> {
        match self {
            Self::Open(raw) => Ok(*raw),
            Self::AttemptingClose | Self::Attempted(_) => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    pub fn close(&mut self, close: impl FnOnce(usize) -> Result<(), i32>) -> io::Result<()> {
        match self {
            Self::Attempted(outcome) => return outcome.map_err(io::Error::from_raw_os_error),
            Self::AttemptingClose => {
                return Err(io::Error::other("original close attempt did not return"));
            }
            Self::Open(_) => {}
        }
        let Self::Open(raw) = std::mem::replace(self, Self::AttemptingClose) else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        // Admission is already gone before the one native call. Unwinding can
        // leave its result unconfirmed, but never authorizes a second close.
        let outcome = close(raw);
        *self = Self::Attempted(outcome);
        outcome.map_err(io::Error::from_raw_os_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn original_close_failure_cannot_be_retried_or_reported_as_success() {
        let mut handle = Handle::Open(17);
        let calls = Cell::new(0);
        let observed = Cell::new(None);
        assert_eq!(handle.original().ok(), Some(17));
        let first = handle.close(|raw| {
            observed.set(Some(raw));
            calls.set(calls.get() + 1);
            Err(5)
        });
        assert_eq!(first.err().and_then(|error| error.raw_os_error()), Some(5));
        assert_eq!(
            handle.original().err().map(|error| error.kind()),
            Some(io::ErrorKind::NotConnected)
        );
        let again = handle.close(|_| {
            calls.set(calls.get() + 1);
            Ok(())
        });
        assert_eq!(again.err().and_then(|error| error.raw_os_error()), Some(5));
        assert_eq!(calls.get(), 1);
        assert_eq!(observed.get(), Some(17));
    }

    #[test]
    fn successful_close_stays_successful_without_another_native_call() {
        let mut handle = Handle::Open(23);
        let calls = Cell::new(0);
        let observed = Cell::new(None);
        let first = handle.close(|raw| {
            observed.set(Some(raw));
            calls.set(calls.get() + 1);
            Ok(())
        });
        assert!(first.is_ok());
        let again = handle.close(|_| {
            calls.set(calls.get() + 1);
            Err(6)
        });
        assert!(again.is_ok());
        assert_eq!(calls.get(), 1);
        assert_eq!(observed.get(), Some(23));
        assert_eq!(
            handle.original().err().map(|error| error.kind()),
            Some(io::ErrorKind::NotConnected)
        );
    }
}
