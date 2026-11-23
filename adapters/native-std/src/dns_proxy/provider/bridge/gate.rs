//! Provider phase and resource admission commit under the same state lock.
use super::super::lease::Counter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Registered,
    Starting,
    Running,
    Stopping,
    Ended,
    Failed,
}
impl Phase {
    pub(super) fn begin_start(&mut self, counter: &Counter) -> bool {
        if *self != Self::Registered {
            return false;
        }
        counter.open();
        *self = Self::Starting;
        true
    }
    #[cfg(any(target_os = "macos", test))]
    pub(super) fn fail_start(&mut self, counter: &Counter) -> bool {
        if *self != Self::Registered {
            return false;
        }
        self.fail(counter);
        true
    }
    pub(super) fn fail(&mut self, counter: &Counter) {
        counter.close();
        *self = Self::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::lease::{Counter, Session};
    use super::Phase;
    use std::{
        io,
        sync::{Arc, Barrier, Mutex},
        thread,
    };

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Concurrent production admission transitions must leave a failed session permanently closed"
    )]
    fn racing_start_and_shutdown_cannot_reopen_resource_admission() -> io::Result<()> {
        for _ in 0..64 {
            let phase = Arc::new(Mutex::new(Phase::Registered));
            let counter = Counter::new(1);
            let rendezvous = Arc::new(Barrier::new(2));
            thread::scope(|threads| -> io::Result<()> {
                let phase_start = Arc::clone(&phase);
                let counter_start = Arc::clone(&counter);
                let start_barrier = Arc::clone(&rendezvous);
                let start = threads.spawn(move || {
                    start_barrier.wait();
                    phase_start
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .begin_start(&counter_start);
                });
                let phase_stop = Arc::clone(&phase);
                let counter_stop = Arc::clone(&counter);
                let stop = threads.spawn(move || {
                    rendezvous.wait();
                    phase_stop
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .fail(&counter_stop);
                });
                start
                    .join()
                    .map_err(|_| io::Error::other("startup transition panicked"))?;
                stop.join()
                    .map_err(|_| io::Error::other("shutdown transition panicked"))?;
                Ok(())
            })?;
            assert_eq!(
                *phase
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                Phase::Failed
            );
            assert!(Session { counter }.lease().is_err());
        }
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "A rejected later startup must not revoke the original active session's resource authority"
    )]
    fn rejected_foreign_start_preserves_existing_session() -> io::Result<()> {
        let counter = Counter::new(1);
        let mut phase = Phase::Registered;
        assert!(phase.begin_start(&counter));
        assert!(!phase.fail_start(&counter));
        let lease = Session { counter }.lease()?;
        drop(lease);
        assert_eq!(phase, Phase::Starting);
        Ok(())
    }
}
