//! Local GET absence and explicit daemon hints can ask the original member to
//! sign a network REQUEST. Only a whole-written GET owns a local completion.

use crate::{clock::Span, types::Intent, *};
use domain::{MessagePhase, OperationPhase};
use gnunet_types::Error as Fault;

#[cfg(all(test, unix))]
mod tests;

#[derive(Clone, Copy)]
enum Phase<'id> {
    Local(Operation<'id>),
    Pending(Trigger),
    Settled,
}

#[derive(Clone, Copy)]
enum Trigger {
    CorrelatedGet,
    DaemonHint,
}

#[derive(Clone, Copy)]
pub(crate) struct Fetch<'id> {
    room: Room<'id>,
    source: Source<'id>,
    epoch: native::Epoch<'id>,
    signer: Identity,
    member: Option<MemberSession<'id>>,
    hash: Hash,
    span: Span,
    required: bool,
    phase: Phase<'id>,
}

impl Fetch<'_> {
    pub(crate) const fn pending_span(&self) -> Option<Span> {
        match self.phase {
            Phase::Pending(_) => Some(self.span),
            Phase::Local(_) | Phase::Settled => None,
        }
    }
}

impl<'id, E: crypto::Entropy, const N: usize> Api<'id, E, N> {
    /// Expire unsent fallback intent independently of Core/native job expiry.
    /// A completed GET with no available member or send credit owns no I/O.
    pub(crate) fn expire_history_gets(&mut self, now: Option<u64>) {
        if self.history_requests.is_empty() {
            return;
        }
        let hard = tokio::time::Instant::now();
        self.history_requests
            .retain(|fetch| hard < fetch.span.hard && now.is_none_or(|n| n < fetch.span.logical));
    }

    pub(crate) fn admit_history_get(
        &mut self,
        room_index: usize,
        hash: Hash,
        span: Span,
        now: u64,
        intent: Intent,
    ) -> Result<Operation<'id>, Error> {
        self.expire_history_gets(Some(now));
        self.history_requests.retain(|fetch| match fetch.phase {
            Phase::Local(op) => self.core.operation_phase(op).is_ok_and(|phase| {
                !matches!(
                    phase,
                    OperationPhase::Complete | OperationPhase::Cancelled | OperationPhase::Failed
                )
            }),
            Phase::Pending(_) | Phase::Settled => true,
        });
        let row = &self.rooms[room_index];
        let room = row.room;
        let source = row.source.ok_or(Fault::StaleGeneration)?;
        let epoch = row.epoch.ok_or(Fault::StaleGeneration)?;
        let signer = row.signer;
        let member = row.member;
        let required = matches!(intent, Intent::Dependency | Intent::DependencyRequest);
        let reserve = hash != [0; 64]
            && !self
                .history_requests
                .iter()
                .any(|fetch| fetch.source == source && fetch.hash == hash);
        if reserve {
            // A last slot belongs to the client's causal dependency GETs even
            // if callers have spent the other original request budgets.
            let limit = if required {
                self.limits.operations
            } else {
                self.limits.operations - 1
            };
            if self.history_requests.len() >= limit {
                return Err(Fault::WouldBlock.into());
            }
        }
        let operation = self.core.request_missing(source, hash, now, span.logical)?;
        self.record_job(room, source, epoch, operation, span, intent)?;
        if reserve {
            self.history_requests.push(Fetch {
                room,
                source,
                epoch,
                signer,
                member,
                hash,
                span,
                required,
                phase: Phase::Local(operation),
            });
        }
        Ok(operation)
    }

    pub(crate) fn missing_history_get(
        &self,
        source: Source<'id>,
        epoch: native::Epoch<'id>,
        hash: &Hash,
    ) -> Option<Operation<'id>> {
        self.leases.iter().find_map(|lease| {
            (lease.source == source
                && lease.epoch == epoch
                && lease.kind == Some(native::Kind::Get)
                && lease
                    .binding
                    .is_some_and(|binding| binding.message() == hash)
                && matches!(lease.exposure, Exposure::Written { .. })
                && self.core.operation_phase(lease.operation) == Ok(OperationPhase::Written))
            .then_some(lease.operation)
        })
    }

    pub(crate) fn accept_history_absence(&mut self, original: Operation<'id>) -> Result<(), Error> {
        if let Some(fetch) = self
            .history_requests
            .iter_mut()
            .find(|fetch| matches!(fetch.phase, Phase::Local(op) if op == original))
        {
            // An optional original GET can become a dependency while written.
            fetch.required |= self
                .core
                .is_required_dependency(fetch.source, &fetch.hash)?;
            fetch.phase = Phase::Pending(Trigger::CorrelatedGet);
        }
        Ok(())
    }

    pub(crate) fn admit_history_hint(
        &mut self,
        index: usize,
        hash: Hash,
        span: Span,
        now: u64,
    ) -> Result<(), Error> {
        if hash == [0; 64] || !self.ready() || span.expired(Some(now)) {
            return Ok(());
        }
        self.expire_history_gets(Some(now));
        let row = &self.rooms[index];
        let (Some(source), Some(epoch)) = (row.source, row.epoch) else {
            return Ok(());
        };
        if Some(epoch) != self.epoch
            || self.history_requests.len() >= self.limits.operations - 1
            || self
                .history_requests
                .iter()
                .any(|fetch| fetch.source == source && fetch.hash == hash)
            || !self.core.source_joined(source)?
        {
            return Ok(());
        }
        let member = match self.active_member_for_history(index) {
            Ok(member) => member,
            Err(Error::Local(Fault::NotReady)) => return Ok(()),
            Err(error) => return Err(error),
        };
        self.history_requests.push(Fetch {
            room: row.room,
            source,
            epoch,
            signer: row.signer,
            member: Some(member),
            hash,
            span,
            required: false,
            phase: Phase::Pending(Trigger::DaemonHint),
        });
        self.wake_domain();
        Ok(())
    }

    pub(crate) fn drive_history_request(&mut self, index: usize, now: u64) -> Result<(), Error> {
        let row = &self.rooms[index];
        if row.closing_span.is_some() || row.close_after.is_some() {
            return Ok(());
        }
        let room = row.room;
        let Some(source) = row.source else {
            return Ok(());
        };
        let epoch = row.epoch.ok_or(Fault::StaleGeneration)?;
        self.history_requests.retain(|fetch| {
            fetch.room != room
                || (fetch.source == source
                    && fetch.epoch == epoch
                    && fetch.signer == row.signer
                    && fetch.member.is_none_or(|member| Some(member) == row.member))
        });
        let mut required = None;
        let mut hint = None;
        let mut optional = None;
        for (slot, fetch) in self.history_requests.iter().enumerate() {
            if fetch.room != room {
                continue;
            }
            match fetch.phase {
                Phase::Pending(Trigger::CorrelatedGet) if fetch.required => {
                    required.get_or_insert(slot);
                }
                Phase::Pending(Trigger::DaemonHint) => {
                    hint.get_or_insert(slot);
                }
                Phase::Pending(Trigger::CorrelatedGet) => {
                    optional.get_or_insert(slot);
                }
                _ => {}
            }
            if required.is_some() && optional.is_some() && hint.is_some() {
                break;
            }
        }
        let hint = if required.is_none()
            && hint.is_some()
            && self
                .core
                .pending_dependencies(room)?
                .any(|(_, original)| original == source)
        {
            None
        } else {
            hint
        };
        let dependency = required
            .or(hint)
            .filter(|_| self.protocol_available(Intent::HistoryRequest { dependency: true }));
        let Some(slot) = dependency.or_else(|| optional.filter(|_| self.free_jobs() > 0)) else {
            return Ok(());
        };
        let fetch = self.history_requests[slot];
        if fetch.span.expired(Some(now))
            || self.core.message(room, &fetch.hash).is_ok_and(|message| {
                message.phase() != MessagePhase::Rejected && message.original_signer().is_some()
            })
        {
            // Keep the original deduplication span when an authentic original
            // arrived before the fallback SEND could be prepared.
            self.history_requests[slot].phase = Phase::Settled;
            self.scan_remaining = self.rooms.len();
            return Ok(());
        }
        let member = match self.active_member_for_history(index) {
            Ok(member) => member,
            Err(Error::Local(Fault::NotReady | Fault::WouldBlock)) => return Ok(()),
            Err(error) => return Err(error),
        };
        if fetch.span.expired(Some(now)) {
            self.history_requests.swap_remove(slot);
            self.scan_remaining = self.rooms.len();
            return Ok(());
        }
        self.next_job.checked_add(1).ok_or(Fault::Overflow)?;
        let pending = match fetch.phase {
            Phase::Pending(Trigger::CorrelatedGet) => self.core.prepare_history_request(
                source,
                member,
                fetch.hash,
                now,
                fetch.span.logical,
            ),
            Phase::Pending(Trigger::DaemonHint) => self.core.prepare_notified_history_request(
                source,
                member,
                fetch.hash,
                now,
                fetch.span.logical,
            ),
            _ => return Err(Fault::Conflict.into()),
        };
        let operation = match pending {
            Ok(operation) => operation,
            Err(domain::Error::Protocol(Fault::Capacity | Fault::NotReady | Fault::WouldBlock)) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        self.record_job(
            room,
            source,
            epoch,
            operation,
            fetch.span,
            Intent::HistoryRequest {
                dependency: dependency.is_some(),
            },
        )?;
        self.history_requests[slot].phase = Phase::Settled;
        Ok(())
    }

    pub(crate) fn retire_history_gets(&mut self, room: Room<'id>) {
        self.history_requests.retain(|fetch| fetch.room != room);
    }
}
