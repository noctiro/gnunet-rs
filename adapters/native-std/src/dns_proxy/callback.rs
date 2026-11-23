//! SDK callback containment and separately observed final argument disposal.
use super::{
    completion::{Publisher, dispose_panic},
    sdk::{NativeFlow, WriteObjects},
};
use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Mutex,
};

/// Declaration order matters: the disposal publisher is dropped after all
/// argument loans and the native flow reference, including during unwinding.
pub(super) struct Callback<T, D = (), F = NativeFlow> {
    publisher: Mutex<Option<Publisher<io::Result<T>>>>,
    _objects: Option<WriteObjects>,
    _flow: F,
    data: D,
    _disposed: Publisher<()>,
    _provider: Option<super::provider::ProviderLease>,
}
impl<T, D, F> Callback<T, D, F> {
    pub(super) fn new(
        publisher: Publisher<io::Result<T>>,
        flow: F,
        disposed: Publisher<()>,
        objects: Option<WriteObjects>,
        data: D,
    ) -> Self {
        Self {
            publisher: Mutex::new(Some(publisher)),
            _objects: objects,
            _flow: flow,
            data,
            _disposed: disposed,
            _provider: None,
        }
    }
    pub(super) fn invoke(&self, result: impl FnOnce() -> io::Result<T>) {
        // No SDK callback may unwind into Objective-C. Taking the unique
        // publisher first also makes duplicate invocations inert.
        contain(|| {
            let publisher = self
                .publisher
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let Some(publisher) = publisher else {
                return;
            };
            let result = match catch_unwind(AssertUnwindSafe(result)) {
                Ok(result) => result,
                Err(payload) => {
                    dispose_panic(payload);
                    Err(io::Error::other("native DNS callback processing panicked"))
                }
            };
            publisher.publish(result);
        });
    }
    pub(super) fn data(&self) -> &D {
        &self.data
    }
    pub(super) fn keep_provider(
        mut self,
        provider: Option<super::provider::ProviderLease>,
    ) -> Self {
        self._provider = provider;
        self
    }
}

// block2 cannot express native thread-safe blocks. Check captured Rust state
// before erasing each closure into its native Block signature.
pub(super) fn thread_safe<F: Send + Sync>(callback: F) -> F {
    callback
}

fn contain(body: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(body)) {
        dispose_panic(payload);
    }
}
