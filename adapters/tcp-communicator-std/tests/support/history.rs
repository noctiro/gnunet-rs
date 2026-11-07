//! Test-only bounded memory history for existing socket/session component models.
//! This is not durable storage, cannot construct real Floor/ReplayPermit, and is
//! never exported or selected by the normal product. No new test is added here.
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_core::session::{ReplayKind, Session, Time};
use gnunet_tcp_communicator_host::{
    self as host, Capacity, Clock, HostError, ManagerCapacity,
    history::{HistoryProgress, ReplayHistory, ReplayTask},
};
use gnunet_types::Error;
use std::{
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};
const MAXIMUM: usize = 4096;
pub struct MemoryHistory {
    rows: Vec<(EddsaPublicKey, ReplayKind, u64)>,
    prepared: Vec<ReplayTask>,
    admitted: Vec<ReplayTask>,
    retired: Vec<ReplayTask>,
    failed: bool,
}
impl MemoryHistory {
    pub fn new() -> Result<Self, Error> {
        let mut rows = Vec::new();
        let mut prepared = Vec::new();
        let mut admitted = Vec::new();
        let mut retired = Vec::new();
        rows.try_reserve_exact(MAXIMUM)
            .map_err(|_| Error::Capacity)?;
        prepared
            .try_reserve_exact(MAXIMUM)
            .map_err(|_| Error::Capacity)?;
        admitted
            .try_reserve_exact(MAXIMUM)
            .map_err(|_| Error::Capacity)?;
        retired
            .try_reserve_exact(MAXIMUM)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            rows,
            prepared,
            admitted,
            retired,
            failed: false,
        })
    }
}
impl ReplayHistory for MemoryHistory {
    fn local_floor(&mut self, task: &ReplayTask) -> Result<Option<u64>, Error> {
        if self.failed {
            return Err(Error::Closed);
        }
        Ok(self
            .rows
            .iter()
            .find(|r| r.0 == task.peer() && r.1 == task.kind())
            .map(|r| r.2))
    }
    fn poll_store(
        &mut self,
        _cx: &mut Context<'_>,
        task: &ReplayTask,
        value: u64,
    ) -> Poll<Result<(), Error>> {
        if self.failed || value < task.stamp() {
            return Poll::Ready(Err(Error::Stale));
        }
        if let Some(row) = self
            .rows
            .iter_mut()
            .find(|r| r.0 == task.peer() && r.1 == task.kind())
        {
            if row.2 > value {
                return Poll::Ready(Err(Error::Stale));
            }
            row.2 = value;
        } else {
            if self.rows.len() == MAXIMUM {
                return Poll::Ready(Err(Error::Capacity));
            }
            self.rows.push((task.peer(), task.kind(), value));
        }
        if !self.prepared.contains(task) {
            if self.prepared.len() == MAXIMUM {
                return Poll::Ready(Err(Error::Capacity));
            }
            self.prepared.push(task.clone());
        }
        Poll::Ready(Ok(()))
    }
    fn store_admitted(&mut self, task: &ReplayTask, _value: u64) {
        if let Some(i) = self.prepared.iter().position(|t| t == task) {
            self.prepared.swap_remove(i);
            if self.admitted.len() == MAXIMUM {
                self.failed = true;
            } else {
                self.admitted.push(task.clone());
            }
        } else {
            self.failed = true;
        }
    }
    fn retire_history(&mut self, task: &ReplayTask) -> Result<(), Error> {
        if self.retired.contains(task) {
            return Ok(());
        }
        if self.retired.len() == MAXIMUM {
            return Err(Error::WouldBlock);
        }
        if let Some(i) = self.prepared.iter().position(|t| t == task) {
            self.prepared.swap_remove(i);
        }
        if let Some(i) = self.admitted.iter().position(|t| t == task) {
            self.admitted.swap_remove(i);
        }
        self.retired.push(task.clone());
        Ok(())
    }
    fn poll_history(&mut self, _cx: &mut Context<'_>) -> Poll<Result<HistoryProgress, Error>> {
        if self.failed {
            return Poll::Ready(Err(Error::Stale));
        }
        match self.retired.pop() {
            Some(task) => Poll::Ready(Ok(HistoryProgress::Retired {
                task,
                uncertain: false,
            })),
            None => Poll::Pending,
        }
    }
}
struct Combined<'a, C> {
    clock: &'a mut C,
    history: &'a mut MemoryHistory,
}
impl<C: Clock> Clock for Combined<'_, C> {
    fn read(&mut self) -> Result<Time, Error> {
        self.clock.read()
    }
    fn revision(&self) -> u64 {
        self.clock.revision()
    }
    fn poll_change(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.clock.poll_change(cx)
    }
}
impl<C> ReplayHistory for Combined<'_, C> {
    fn local_floor(&mut self, t: &ReplayTask) -> Result<Option<u64>, Error> {
        self.history.local_floor(t)
    }
    fn poll_store(
        &mut self,
        cx: &mut Context<'_>,
        t: &ReplayTask,
        s: u64,
    ) -> Poll<Result<(), Error>> {
        self.history.poll_store(cx, t, s)
    }
    fn store_admitted(&mut self, t: &ReplayTask, s: u64) {
        self.history.store_admitted(t, s)
    }
    fn retire_history(&mut self, t: &ReplayTask) -> Result<(), Error> {
        self.history.retire_history(t)
    }
    fn poll_history(&mut self, cx: &mut Context<'_>) -> Poll<Result<HistoryProgress, Error>> {
        self.history.poll_history(cx)
    }
}
pub struct Communicator<'a> {
    inner: host::Communicator<'a>,
    history: MemoryHistory,
}
impl<'a> Communicator<'a> {
    pub fn new(
        services: [Connection; 2],
        capacity: Capacity,
        manager: ManagerCapacity,
    ) -> Result<Self, HostError> {
        let history = MemoryHistory::new()?;
        Ok(Self {
            inner: host::Communicator::new(services, capacity, manager)?,
            history,
        })
    }
    pub async fn step(
        &mut self,
        time: Time,
        rng: &mut impl Entropy,
    ) -> Result<host::Progress, HostError> {
        self.inner.step(time, &mut self.history, rng).await
    }
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        time: Time,
        rng: &mut impl Entropy,
    ) -> Poll<Result<host::Progress, HostError>> {
        self.inner.poll_step(cx, time, &mut self.history, rng)
    }
}
impl<'a> Deref for Communicator<'a> {
    type Target = host::Communicator<'a>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for Communicator<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
pub struct Driver<'a> {
    inner: host::Driver<'a>,
    history: MemoryHistory,
}
impl<'a> Driver<'a> {
    pub fn new(
        core: Session<'a>,
        peer: Connection,
        services: [Connection; 2],
        capacity: Capacity,
        address: &[u8],
        network: u32,
    ) -> Result<Self, HostError> {
        let history = MemoryHistory::new()?;
        Ok(Self {
            inner: host::Driver::new(core, peer, services, capacity, address, network)?,
            history,
        })
    }
    pub async fn step(
        &mut self,
        time: Time,
        rng: &mut impl Entropy,
    ) -> Result<host::Activity, HostError> {
        self.inner.step(time, &mut self.history, rng).await
    }
    pub async fn drive(
        &mut self,
        clock: &mut impl Clock,
        rng: &mut impl Entropy,
    ) -> Result<host::Activity, HostError> {
        let mut ports = Combined {
            clock,
            history: &mut self.history,
        };
        self.inner.drive(&mut ports, rng).await
    }
}
impl<'a> Deref for Driver<'a> {
    type Target = host::Driver<'a>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for Driver<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
