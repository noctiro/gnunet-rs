//! Linear handoff of the original IPC owner after all peer authority retired.
use super::*;

/// Original service framing, serial namespaces and registration without a peer key.
/// Only a fully retired communicator can create this owner.
pub struct Resources {
    original: Box<Communicator<'static>>,
}

impl<'a> Communicator<'a> {
    /// Old peer debt and every already-read service frame reached a boundary.
    #[must_use]
    pub fn identity_quiescent(&self) -> bool {
        self.is_quiescent() && self.peerstore.input_idle() && self.transport.input_idle()
    }
    /// Release all session borrows while retaining the exact original IPC owners.
    /// Pending peer, replay, callback or copied output debt refuses the handoff.
    /// Failure returns this same original communicator without replacing its MQ.
    #[expect(
        clippy::result_large_err,
        reason = "A refused handoff retains the original framing and authority without allocating another owner"
    )]
    pub fn into_resources(self) -> Result<Resources, Rejected<Self>> {
        if !self.is_empty()
            || !self.is_quiescent()
            || self.history_tainted
            || self.admission == Admission::Stopping
            || !self.identity_quiescent()
        {
            return Err(Rejected {
                reason: Error::WouldBlock,
                value: self,
            });
        }
        let prepared = (|| {
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(self.slots.len())
                .map_err(|_| Error::Capacity)?;
            for slot in &self.slots {
                slots.push(Slot {
                    generation: slot.generation,
                    peer: None,
                });
            }
            Ok::<_, Error>((
                slots,
                empty_slots(self.queries.len())?,
                empty_slots(self.stores.len())?,
                empty_slots(self.flows.len())?,
            ))
        })();
        let (slots, queries, stores, flows) = match prepared {
            Ok(prepared) => prepared,
            Err(reason) => {
                return Err(Rejected {
                    reason,
                    value: self,
                });
            }
        };
        let Self {
            owner,
            capacity,
            queue_capacity,
            callbacks,
            generation,
            peerstore,
            transport,
            peerstore_epoch,
            transport_epoch,
            histories,
            retired_metrics,
            history_tainted,
            rid,
            fc,
            qid,
            command_serial,
            commands,
            scratch,
            announce,
            task_cursor,
            timer,
            timer_key,
            ..
        } = self;
        Ok(Resources {
            original: Box::new(Communicator {
                owner,
                slots,
                capacity,
                queue_capacity,
                callbacks,
                generation,
                peerstore,
                transport,
                peerstore_epoch,
                transport_epoch,
                queries,
                histories,
                retired_metrics,
                history_tainted,
                stores,
                flows,
                rid,
                fc,
                qid,
                command_serial,
                commands,
                scratch,
                announce,
                admission: Admission::IdentityRetiring,
                task_cursor,
                timer,
                timer_key,
            }),
        })
    }
}

impl Resources {
    /// Whether retained input can enter a new peer admission context.
    #[must_use]
    pub fn input_idle(&self) -> bool {
        self.original.peerstore.input_idle() && self.original.transport.input_idle()
    }
    /// Check the original fixed IPC/session policy before lending fresh backing.
    #[must_use]
    pub fn matches_policy(&self, ipc: Capacity, capacity: ManagerCapacity) -> bool {
        self.original.capacity.sessions == capacity.sessions
            && self.original.capacity.pending_sends == capacity.pending_sends
            && self.original.capacity.commands == capacity.commands
            && self.original.callbacks == ipc.callbacks
            && self
                .original
                .peerstore
                .matches_capacity(ipc.ipc_bytes, ipc.ipc_frames)
            && self
                .original
                .transport
                .matches_capacity(ipc.ipc_bytes, ipc.ipc_frames)
    }
    /// Lend the same registered IPC owner to a fresh peer generation.
    /// Counters, RX framing and physical source epochs are never reset.
    pub fn resume<'next>(self) -> Result<Communicator<'next>, Rejected<Self>> {
        if !self.input_idle() {
            return Err(Rejected {
                reason: Error::WouldBlock,
                value: self,
            });
        }
        let mut original = self.original;
        original.admission = Admission::Open;
        Ok(*original)
    }
    /// Actual physical TRANSPORT generation retained by this owner.
    #[must_use]
    pub fn transport_epoch(&self) -> u64 {
        self.original.transport_epoch()
    }
    /// Whether the same original TRANSPORT owner remains connected.
    #[must_use]
    pub fn transport_online(&self) -> bool {
        self.original.transport_online()
    }
    /// Retain an original address intent while peer authority is absent.
    pub fn advertise(&mut self, id: u32, address: &[u8], network: u32) -> Result<(), HostError> {
        self.original.advertise(id, address, network)
    }
    /// Withdraw an original address through its unchanged physical FIFO.
    pub fn withdraw(&mut self, id: u32) -> Result<(), HostError> {
        self.original.withdraw(id)
    }
    /// Drive only service framing, rejecting CREATE until a peer owner resumes.
    /// No session, entropy, signature or durable replay effect can be admitted.
    pub fn poll(&mut self, cx: &mut Context<'_>, now: u64) -> Poll<Result<Progress, OwnedFailure>> {
        let time = Time { now, signed: 0 };
        // All key-bearing rows were removed by into_resources. The original
        // service protocol parser still owns partial input and negative replies.
        self.original
            .poll_step_owned(cx, time, &mut NoAuthority, &mut NoAuthority)
    }
}

struct NoAuthority;
impl Entropy for NoAuthority {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::NotReady)
    }
}
impl ReplayHistory for NoAuthority {
    fn local_floor(&mut self, _: &ReplayTask) -> Result<Option<u64>, Error> {
        Err(Error::NotReady)
    }
    fn poll_store(
        &mut self,
        _: &mut Context<'_>,
        _: &ReplayTask,
        _: u64,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(Err(Error::NotReady))
    }
    fn store_admitted(&mut self, _: &ReplayTask, _: u64) {}
    fn retire_history(&mut self, _: &ReplayTask) -> Result<(), Error> {
        Err(Error::NotReady)
    }
    fn poll_history(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<crate::history::HistoryProgress, Error>> {
        Poll::Pending
    }
}
