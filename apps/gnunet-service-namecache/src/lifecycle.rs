//! Bounded independent original Resolver/statistics emergency cleanup causes.
use crate::Failure;
use gnunet_ipc_unix::producer;
use std::{cell::RefCell, fmt, rc::Rc};
#[derive(Clone, Default)]
pub(super) struct Cleanup(Rc<RefCell<Deferred>>);
#[derive(Debug, Default)]
struct Deferred {
    resolver: Option<Failure>,
    statistics: Option<producer::Failure>,
}
#[derive(Debug)]
struct Failed {
    original: Option<Failure>,
    cleanup: Deferred,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NAMECACHE original={:?}; independent Resolver cleanup={:?}; statistics cleanup={:?}",
            self.original, self.cleanup.resolver, self.cleanup.statistics
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.resolver.as_deref())
            .or(self
                .cleanup
                .statistics
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
    }
}
impl Cleanup {
    pub(super) fn retain(&self, error: Failure) {
        let mut state = self.0.borrow_mut();
        if state.resolver.is_none() {
            state.resolver = Some(error);
        }
    }
    pub(super) fn retain_statistics(&self, error: producer::Failure) {
        let mut state = self.0.borrow_mut();
        if state.statistics.is_none() {
            state.statistics = Some(error);
        }
    }
    pub(super) fn finish<T>(&self, result: Result<T, Failure>) -> Result<T, Failure> {
        let cleanup = std::mem::take(&mut *self.0.borrow_mut());
        if cleanup.resolver.is_none() && cleanup.statistics.is_none() {
            result
        } else {
            Err(Box::new(Failed {
                original: result.err(),
                cleanup,
            }))
        }
    }
}
