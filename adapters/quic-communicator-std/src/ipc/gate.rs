//! A retained connect callback reads the same bound used by framed IPC work.
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error;
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

pub(super) struct Gate {
    hard: Instant,
    clock: Arc<dyn RuntimeClock>,
    recovery: Mutex<Option<(Instant, u64)>>,
}
impl Gate {
    pub fn new(hard: Instant, clock: Arc<dyn RuntimeClock>) -> Self {
        Self {
            hard,
            clock,
            recovery: Mutex::new(None),
        }
    }
    pub fn set(&self, bound: Option<(Instant, u64)>) -> Result<(), Error> {
        *self.recovery.lock().map_err(|_| Error::Unavailable)? = bound;
        Ok(())
    }
    fn snapshot(&self) -> Result<Option<(Instant, u64)>, Error> {
        self.recovery
            .lock()
            .map(|bound| *bound)
            .map_err(|_| Error::Unavailable)
    }
    pub fn hard(&self) -> Result<Instant, Error> {
        Ok(self
            .snapshot()?
            .map_or(self.hard, |(hard, _)| hard.min(self.hard)))
    }
    pub fn check(&self) -> Result<(), Error> {
        // Only the exclusive Ipc owner mutates this bound; its retained native
        // connector shares read access. No mutex is held across a clock port.
        let scope = self.snapshot()?;
        let hard = scope.map_or(self.hard, |(hard, _)| hard.min(self.hard));
        if Instant::now() >= hard {
            return Err(Error::Deadline);
        }
        if let Some((_, until)) = scope {
            let sample = self.clock.sample();
            if Instant::now() >= hard {
                return Err(Error::Deadline);
            }
            if sample?.now.as_micros() >= until {
                return Err(Error::Deadline);
            }
        }
        Ok(())
    }
}
