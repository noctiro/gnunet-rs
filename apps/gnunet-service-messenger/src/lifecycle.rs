//! Bounded independent original and cleanup causes; no logger-success dependency.
use crate::Failure;
use std::{cell::RefCell, fmt, rc::Rc};
#[derive(Clone, Default)]
pub(super) struct Cleanup(Rc<RefCell<Deferred>>);
#[derive(Default, Debug)]
struct Deferred {
    server: Option<Failure>,
    resolver: Option<Failure>,
    statistics: Option<Failure>,
}
#[derive(Clone, Copy)]
pub(super) enum Owner {
    Server,
    Resolver,
    Statistics,
}
#[derive(Default, Debug)]
pub(super) struct Failures {
    pub original: Option<Failure>,
    pub history: Option<Failure>,
    pub pending_history: Option<Failure>,
    pub server: Option<Failure>,
    pub resolver: Option<Failure>,
    pub statistics: Option<Failure>,
    pub output: Option<std::io::Error>,
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MESSENGER original={:?}; history={:?}; pending-history={:?}; server-cleanup={:?}; Resolver-cleanup={:?}; STATISTICS={:?}; output={:?}",
            self.original,
            self.history,
            self.pending_history,
            self.server,
            self.resolver,
            self.statistics,
            self.output
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.history.as_deref())
            .or(self.pending_history.as_deref())
            .or(self.server.as_deref())
            .or(self.resolver.as_deref())
            .or(self.statistics.as_deref())
            .or(self.output.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
impl Failures {
    pub(super) fn finish(self) -> Result<(), Failure> {
        if self.original.is_none()
            && self.history.is_none()
            && self.pending_history.is_none()
            && self.server.is_none()
            && self.resolver.is_none()
            && self.statistics.is_none()
            && self.output.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl Cleanup {
    pub(super) fn retain(&self, owner: Owner, error: Failure) {
        let mut pending = self.0.borrow_mut();
        let slot = match owner {
            Owner::Server => &mut pending.server,
            Owner::Resolver => &mut pending.resolver,
            Owner::Statistics => &mut pending.statistics,
        };
        // Each physical owner is closed once; retain the first original cause.
        if slot.is_none() {
            *slot = Some(error);
        }
    }
    pub(super) fn finish(&self, result: Result<(), Failure>) -> Result<(), Failure> {
        let pending = std::mem::take(&mut *self.0.borrow_mut());
        if pending.server.is_none() && pending.resolver.is_none() && pending.statistics.is_none() {
            result
        } else {
            Err(Box::new(Emergency {
                original: result.err(),
                deferred: pending,
            }))
        }
    }
}

#[derive(Debug)]
struct Emergency {
    original: Option<Failure>,
    deferred: Deferred,
}
impl fmt::Display for Emergency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MESSENGER original={:?}; deferred original cleanup={:?}",
            self.original, self.deferred
        )
    }
}
impl std::error::Error for Emergency {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.deferred.server.as_deref())
            .or(self.deferred.resolver.as_deref())
            .or(self.deferred.statistics.as_deref())
    }
}
