//! Fixed original-request loans survive lost poll owners and pending approvals.
use super::{MAX_OPERATIONS, delegate::Delegate, sdk};
use crate::dns_proxy::completion::Publisher;
use block2::RcBlock;
use objc2::rc::Retained;
use std::{cell::RefCell, io, rc::Rc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Key {
    slot: usize,
    generation: u64,
}
enum Stage {
    Reserved,
    Submitted(Loan),
    Retiring,
}
struct Record {
    key: Key,
    identifier: String,
    stage: Stage,
}
struct Registry {
    generation: u64,
    entries: [Option<Record>; MAX_OPERATIONS],
}
thread_local! {
    static REGISTRY: RefCell<Registry> = RefCell::new(Registry {
        generation: 0, entries: std::array::from_fn(|_|None)
    });
}
pub(super) struct Reservation {
    key: Key,
    committed: bool,
}
pub(super) fn reserve(identifier: &str) -> io::Result<Reservation> {
    REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        if registry
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.identifier == identifier)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "system-extension request for this bundle is still pending",
            ));
        }
        let slot = registry
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "original system-extension callback capacity is exhausted",
                )
            })?;
        let generation = registry
            .generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("system-extension request generation overflow"))?;
        let key = Key { slot, generation };
        registry.generation = generation;
        registry.entries[slot] = Some(Record {
            key,
            identifier: identifier.to_owned(),
            stage: Stage::Reserved,
        });
        Ok(Reservation {
            key,
            committed: false,
        })
    })
}
impl Reservation {
    pub(super) const fn key(&self) -> Key {
        self.key
    }
    pub(super) fn submit(
        mut self,
        request: Retained<sdk::Request>,
        delegate: Retained<Delegate>,
        disposed: Publisher<()>,
    ) -> io::Result<()> {
        let manager = sdk::manager()?;
        let submitted = request.clone();
        REGISTRY.with(|registry| {
            let mut registry = registry.borrow_mut();
            let record = registry.entries[self.key.slot]
                .as_mut()
                .filter(|entry| entry.key == self.key)
                .ok_or_else(|| io::Error::other("original extension reservation disappeared"))?;
            record.stage = Stage::Submitted(Loan {
                request,
                _delegate: delegate,
                _release: ReleaseSlot(self.key),
                _disposed: disposed,
            });
            Ok::<_, io::Error>(())
        })?;
        self.committed = true;
        sdk::submit(&manager, &submitted);
        Ok(())
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            clear(self.key);
        }
    }
}
pub(super) fn matches(key: Key, request: &sdk::Request) -> bool {
    REGISTRY.with(|registry|registry.borrow().entries[key.slot].as_ref().is_some_and(|entry|
        entry.key==key && matches!(&entry.stage,Stage::Submitted(loan) if std::ptr::eq(&*loan.request,request))))
}
pub(super) fn take(key: Key, request: &sdk::Request) -> Option<Loan> {
    if !matches(key, request) {
        return None;
    }
    REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let record = registry.entries[key.slot].as_mut()?;
        match std::mem::replace(&mut record.stage, Stage::Retiring) {
            Stage::Submitted(loan) => Some(loan),
            _ => None,
        }
    })
}
fn clear(key: Key) {
    // Outstanding approval requests can outlive the poll owner and the main
    // application loop. TLS teardown is process exit, not a native receipt;
    // releasing the last loan must not re-enter a destroyed TLS registry.
    let removed = REGISTRY.try_with(|registry| {
        let mut registry = registry.borrow_mut();
        if registry.entries[key.slot]
            .as_ref()
            .is_some_and(|entry| entry.key == key)
        {
            registry.entries[key.slot].take()
        } else {
            None
        }
    });
    drop(removed);
}
struct ReleaseSlot(Key);
impl Drop for ReleaseSlot {
    fn drop(&mut self) {
        clear(self.0);
    }
}
pub(super) struct Loan {
    request: Retained<sdk::Request>,
    _delegate: Retained<Delegate>,
    _release: ReleaseSlot,
    // Final publication can become observable only after both native retains
    // and the original bounded registry reservation have been released.
    _disposed: Publisher<()>,
}
pub(super) struct Release {
    loan: Rc<RefCell<Option<Loan>>>,
    block: RcBlock<dyn Fn()>,
}
impl Release {
    pub(super) fn reserve() -> Self {
        let loan = Rc::new(RefCell::new(None));
        let retained = Rc::clone(&loan);
        let block = RcBlock::new(move || {
            let _keep_original_loan = &retained;
        });
        Self { loan, block }
    }
    pub(super) fn submit(self, loan: Loan) {
        self.loan.replace(Some(loan));
        sdk::defer_release(&self.block);
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_OPERATIONS, reserve};
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Only local admission records are exercised; no SDK object is constructed or submitted"
    )]
    fn pending_original_capacity_and_bundle_exclusivity_are_bounded() -> std::io::Result<()> {
        let first = reserve("org.example.original")?;
        assert!(
            reserve("org.example.original")
                .is_err_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists)
        );
        let mut remaining = Vec::new();
        for i in 1..MAX_OPERATIONS {
            remaining.push(reserve(&format!("org.example.original{i}"))?);
        }
        assert!(
            reserve("org.example.full")
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
        );
        drop(first);
        let replacement = reserve("org.example.original")?;
        drop(remaining);
        drop(replacement);
        Ok(())
    }
}
