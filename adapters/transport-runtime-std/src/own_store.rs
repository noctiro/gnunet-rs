//! Exact managed-projection ownership across the actual fenced Journal port.
use crate::own::{OwnRecordBackend, OwnedProjection, RejectedProjection};
use gnunet_transport::{
    PeerId,
    own::{CommitOutcome, RecordProvenance},
};
use gnunet_transport_host::peerstore::{
    Journal, JournalFailure, JournalTransaction, ManagedAddress,
};
use gnunet_types::Error;

/// Original projection and real filesystem transaction retained together. It is
/// neither a cloned snapshot nor a reconstructed token after an unknown write.
#[must_use = "Retain the original managed transaction until its known outcome or exact recovery."]
pub struct ManagedTransaction {
    projection: OwnedProjection,
    journal: JournalTransaction,
}
impl ManagedTransaction {
    /// Original complete desired projection, including staged/current provenance.
    pub fn projection(&self) -> &OwnedProjection {
        &self.projection
    }
    /// Actual native publication certainty for this exact original transaction.
    pub fn outcome(&self) -> Option<CommitOutcome> {
        self.journal.outcome()
    }
    /// Original native failure, retained through later recovery attempts.
    pub fn failure(&self) -> Option<&JournalFailure> {
        self.journal.failure()
    }
    /// Transfer the original exact native cause after the coordinator consumes
    /// its transaction outcome; no OS error is reconstructed.
    pub fn take_failure(&mut self) -> Option<JournalFailure> {
        self.journal.take_failure()
    }
    /// Latest recovery refusal, independent of the original failure.
    pub fn recovery_failure(&self) -> Option<&JournalFailure> {
        self.journal.recovery_failure()
    }
}

/// A synchronous port borrowing the one real Journal writer and its actual
/// current clock sample. It creates no worker, thread, socket or signing request.
pub struct JournalBackend<'a> {
    journal: &'a mut Journal,
    now: u64,
}
impl<'a> JournalBackend<'a> {
    /// Bind this preparation turn to its real current time. The original Journal
    /// independently verifies every public artifact and its retained writer fence.
    pub fn at(journal: &'a mut Journal, now: u64) -> Self {
        Self { journal, now }
    }
    /// Settle an original prepared projection before publication starts. The
    /// complete projection remains in its transaction for the caller's actual
    /// lifecycle result; an Unknown transaction is never treated as aborted.
    pub fn abort_own(&mut self, original: &mut ManagedTransaction) -> Result<CommitOutcome, Error> {
        self.journal.abort_prepared(&mut original.journal)
    }
}
impl OwnRecordBackend for JournalBackend<'_> {
    type Transaction = ManagedTransaction;
    fn prepare_own(
        &mut self,
        original: OwnedProjection,
    ) -> Result<Self::Transaction, RejectedProjection> {
        let candidate = (|| {
            let mut addresses = Vec::new();
            addresses
                .try_reserve_exact(original.records().len())
                .map_err(|_| Error::Capacity)?;
            for record in original.records() {
                if record.provenance() == RecordProvenance::Committed && record.expiry() <= self.now
                {
                    return Err(Error::Stale);
                }
                addresses.push(ManagedAddress {
                    value: record.value(),
                    expiry: record.expiry(),
                });
            }
            self.journal.prepare_managed(
                PeerId(*original.authority().peer().as_bytes()),
                &addresses,
                original.hello(),
                self.now,
            )
        })();
        match candidate {
            Ok(journal) => Ok(ManagedTransaction {
                projection: original,
                journal,
            }),
            Err(cause) => Err(RejectedProjection { original, cause }),
        }
    }
    fn commit_own(&mut self, original: &mut Self::Transaction) -> CommitOutcome {
        self.journal.commit(&mut original.journal)
    }
    fn recover_own(&mut self, original: &mut Self::Transaction) -> CommitOutcome {
        self.journal.recover(&mut original.journal)
    }
    fn own_io_quiescent(&self, original: &Self::Transaction) -> bool {
        self.journal.io_quiescent(&original.journal)
    }
}
