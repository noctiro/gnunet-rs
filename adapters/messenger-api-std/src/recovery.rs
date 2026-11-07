//! Logical membership intent is separate from retired physical jobs and bytes.
use crate::{api::Api, clock::Span, types::*, *};
use domain::OperationPhase;
use gnunet_types::Error as Fault;
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) struct Membership<'a> {
    pub room: Room<'a>,
    pub door: Option<[u8; 32]>,
    // Before the first actual reply, the caller's original bound still applies.
    // Established membership lives until explicit close/stop, not until an old
    // already-completed OPEN operation's timeout.
    pub pending: Option<Span>,
    pub operation: Option<Operation<'a>>,
    pub restored: bool,
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    pub(crate) fn membership_capacity(
        &self,
        key: &Hash,
        door: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        let exists = self.rooms.iter().find(|r| &r.key == key).is_some_and(|r| {
            self.memberships
                .iter()
                .any(|m| m.room == r.room && m.door == door)
        });
        if !exists && self.memberships.len() == self.limits.operations {
            return Err(Fault::Capacity.into());
        }
        Ok(())
    }
    pub(crate) fn remember_membership(
        &mut self,
        room: Room<'a>,
        door: Option<[u8; 32]>,
        span: Span,
        operation: Operation<'a>,
    ) {
        self.observe_memberships();
        if let Some(m) = self
            .memberships
            .iter_mut()
            .find(|m| m.room == room && m.door == door)
        {
            m.operation = Some(operation);
            m.restored = true;
        } else {
            // Storage was reserved before IO and capacity checked before the
            // operation was admitted; this push cannot grow the bounded table.
            self.memberships.push(Membership {
                room,
                door,
                pending: Some(span),
                operation: Some(operation),
                restored: true,
            });
        }
    }
    pub(crate) fn observe_memberships(&mut self) {
        for membership in &mut self.memberships {
            if membership.operation.is_some_and(|operation| {
                self.core
                    .operation_phase(operation)
                    .is_ok_and(|p| p == OperationPhase::Complete)
            }) {
                membership.pending = None;
                membership.operation = None;
            }
        }
        if self.restoring
            && self.memberships.iter().all(|m| {
                m.restored && m.operation.is_none() && self.core.joined(m.room).unwrap_or(false)
            })
        {
            self.restoring = false;
            self.reconnect_delay = Duration::from_millis(100);
        }
    }
    /// Whether this actual physical loss permits retaining the logical room
    /// intent. No old job or SEND/STORE frame is authorized by this predicate.
    #[must_use]
    pub fn can_reconnect(&self, loss: &Loss<'_>) -> bool {
        if self.closed
            || self.fenced
            || self.disconnecting
            || self.running
            || loss.layout_need().is_some()
            || loss.primary_error().is_some()
            || !loss.cleanup_errors().is_empty()
            || !self
                .memberships
                .iter()
                .any(|m| m.pending.is_none_or(|span| !span.expired(None)))
        {
            return false;
        }
        match loss.cause() {
            StopCause::Native => matches!(
                &loss.native().cause,
                native::LossCause::Eof
                    | native::LossCause::InputDeadline
                    | native::LossCause::InitialDeadline
                    | native::LossCause::Failure(native::Error::Io(_))
            ),
            StopCause::Deadline(_) => loss.subscription_deadline,
            StopCause::Initialization => {
                self.restoring
                    && loss
                        .control()
                        .is_some_and(|c| c.kind() == native::Kind::Create)
            }
            _ => false,
        }
    }
    pub(crate) fn retire_stopped_operations(&mut self) -> Result<(), Error> {
        // The previous Loss was consumed and the source is physically stopped.
        // Bounded terminal slots can now retire without adopting any old work.
        for index in 0..self.rooms.len() {
            let room = self.rooms[index].room;
            let count = self.core.operations(room)?.count();
            let expected = count
                .checked_mul(core::mem::size_of::<Operation<'a>>())
                .ok_or(Fault::Overflow)?;
            if self
                .retained_overhead()?
                .checked_add(expected)
                .is_none_or(|n| n > self.limits.bytes)
            {
                return Err(Fault::Capacity.into());
            }
            let mut terminal = Vec::new();
            terminal
                .try_reserve_exact(count)
                .map_err(|_| Fault::Capacity)?;
            let scratch = terminal
                .capacity()
                .checked_mul(core::mem::size_of::<Operation<'a>>())
                .ok_or(Fault::Overflow)?;
            if self
                .retained_overhead()?
                .checked_add(scratch)
                .is_none_or(|n| n > self.limits.bytes)
            {
                return Err(Fault::Capacity.into());
            }
            for (binding, phase) in self.core.operations(room)? {
                if !matches!(
                    phase,
                    OperationPhase::Complete | OperationPhase::Failed | OperationPhase::Cancelled
                ) {
                    return Err(Fault::NotReady.into());
                }
                terminal.push(binding.operation());
            }
            for operation in terminal {
                self.core.retire_operation(operation)?;
            }
        }
        Ok(())
    }
    pub(crate) fn restore_memberships(&mut self, now: u64) -> Result<(), Error> {
        if !self.restoring || !self.ready() {
            return Ok(());
        }
        self.memberships
            .retain(|m| m.pending.is_none_or(|span| !span.expired(Some(now))));
        // A restored or JOIN-blocked row is only metadata to inspect, not an
        // admitted effect. Visit at most this bounded ledger once so a small
        // work budget cannot strand a later ready membership without a wake.
        let mut admitted = 0;
        for _ in 0..self.memberships.len() {
            if admitted == self.limits.work_per_poll || self.free_jobs() == 0 {
                break;
            }
            let index = self.membership_cursor % self.memberships.len();
            self.membership_cursor = (index + 1) % self.memberships.len();
            let membership = self.memberships[index];
            if membership.restored {
                continue;
            }
            let row = self.room_index(membership.room)?;
            if self.rooms[row].source.is_some()
                && (self.rooms[row].join.is_some() || !self.core.joined(membership.room)?)
            {
                continue;
            }
            let identity = self.rooms[row].signer;
            let key = self.rooms[row].key;
            let span = match membership.pending {
                Some(span) => span,
                None => Span::new(now, self.limits.operation_lifetime)?,
            };
            self.admission_bounded(Deadline {
                owner: self.owner,
                span,
            })?;
            let (_, room, source, epoch) = self.room_source_as(key, identity)?;
            let result = match membership.door {
                None => self.core.open(source, span.logical),
                Some(door) => self.core.enter(source, door, span.logical),
            };
            let operation = match result {
                Ok(operation) => operation,
                Err(domain::Error::Protocol(Fault::NotReady | Fault::WouldBlock)) => continue,
                Err(error) => return Err(error.into()),
            };
            self.record_job(room, source, epoch, operation, span, Intent::Membership)?;
            self.memberships[index].operation = Some(operation);
            self.memberships[index].restored = true;
            admitted += 1;
        }
        Ok(())
    }
}
