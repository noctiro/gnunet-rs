//! Admission and completion for hosts that yield during backend operations.

use super::{
    ClientId, ENTRY_OVERHEAD, Entropy, Fault, Instance, ReplyAction, Service, required_output,
};
use crate::backend::{Backend, BackendError, Put, PutPolicy, PutReport, Record, Selection, Usage};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Data, Request, Response},
};

/// One admitted operation. The command borrows the original immutable request.
pub enum Command<'request> {
    /// Insert or merge using the policy captured at admission.
    Put(Put<'request>, PutPolicy),
    /// Remove the exact key and bytes.
    Remove {
        /// Original datastore key.
        key: &'request [u8; 64],
        /// Original value.
        value: &'request [u8],
    },
    /// Select using the original parameters and, when needed, sampled entropy.
    Select(Selection<'request>, u64),
}

impl Command<'_> {
    fn kind(&self) -> Kind {
        match self {
            Self::Put(..) => Kind::Put,
            Self::Remove { .. } => Kind::Remove,
            Self::Select(..) => Kind::Select,
        }
    }

    pub(super) fn execute<B: Backend>(self, backend: &mut B) -> Completion<'_, B::Error> {
        match self {
            Self::Put(put, policy) => Completion::Put(backend.put(put, policy)),
            Self::Remove { key, value } => Completion::Remove(backend.remove(key, value)),
            Self::Select(selection, random) => {
                Completion::Select(backend.select(selection, random))
            }
        }
    }
}

/// The only completion accepted for an admitted command.
pub enum Completion<'value, E> {
    /// The PUT and its reclamation have settled.
    Put(Result<PutReport, E>),
    /// The removal has settled.
    Remove(Result<bool, E>),
    /// The read and any replication decrement have settled.
    Select(Result<Option<Record<'value>>, E>),
}

/// The exact original command, scoped to one service owner.
#[derive(Debug)]
pub struct WorkId<'id> {
    owner: &'id Instance,
    serial: u64,
}

/// Immediate service reply or one command to run through the matching backend.
pub enum Dispatch<'id, 'request, E> {
    /// Admission produced the complete response or no-response disposition.
    Reply(ReplyAction<E>),
    /// Complete or cancel this exact operation before admitting another command.
    Run {
        /// Original operation identifier.
        id: WorkId<'id>,
        /// The validated operation and its captured policy.
        command: Command<'request>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Put,
    Remove,
    Select,
}

struct ReplyContext {
    required: usize,
    hint: AbsoluteTime,
}

pub(super) struct Pending {
    pub(super) client: u64,
    kind: Kind,
    reply: ReplyContext,
}

impl<E> Completion<'_, E> {
    fn kind(&self) -> Kind {
        match self {
            Self::Put(_) => Kind::Put,
            Self::Remove(_) => Kind::Remove,
            Self::Select(_) => Kind::Select,
        }
    }
}

impl<'id> Service<'id, '_> {
    /// Admit a validated official request once. Supply authoritative backend
    /// usage for reservation admission. A pending command excludes all other
    /// admissions and maintenance until it settles.
    pub fn begin<'request, E>(
        &mut self,
        client: ClientId<'id>,
        request: Request<'request>,
        usage: impl FnOnce() -> Usage,
        output: &mut [u8],
        now: AbsoluteTime,
        entropy: &mut impl Entropy,
    ) -> Result<Dispatch<'id, 'request, E>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if self.fenced {
            return Err(Error::OutcomeUnknown);
        }
        self.index(client)?;
        if self.work.is_some() {
            return Err(Error::WouldBlock);
        }
        request.encoded_len()?;
        let required = required_output(request);
        if output.len() < required {
            return Err(Error::Capacity);
        }
        let hint = self.min_expiration;
        let reply = |action: Result<ReplyAction<E>, Error>| action.map(Dispatch::Reply);
        let command = match request {
            Request::Reserve { amount, entries } => {
                return reply(self.reserve(client, amount, entries, usage(), output));
            }
            Request::Release { reservation } => {
                let Some(index) = self.reservation(client, reservation) else {
                    return reply(self.status(
                        output,
                        -1,
                        Some(b"Could not find matching reservation\0"),
                        hint,
                        None,
                    ));
                };
                self.reserved = self
                    .reserved
                    .checked_sub(self.reservations[index].remaining)
                    .ok_or(Error::InvalidInput)?;
                self.reservations[index] = Default::default();
                return reply(self.status(output, 1, None, hint, None));
            }
            Request::Drop => {
                self.drop_on_shutdown = true;
                return Ok(Dispatch::Reply(ReplyAction::NoReply));
            }
            Request::Put(data) => {
                // An admitted PUT consumes the covered quota once, including
                // when it merges, is cancelled, or fails before backend commit.
                if data.reservation != 0 {
                    let Some(index) = self.reservation(client, data.reservation) else {
                        return reply(self.status(
                            output,
                            -1,
                            Some(b"Could not find matching reservation\0"),
                            hint,
                            None,
                        ));
                    };
                    let charge = (data.value.len() as u64)
                        .checked_add(ENTRY_OVERHEAD)
                        .ok_or(Error::Overflow)?;
                    let spent = self.reservations[index].remaining.min(charge);
                    self.reserved = self
                        .reserved
                        .checked_sub(spent)
                        .ok_or(Error::InvalidInput)?;
                    self.reservations[index].remaining -= spent;
                }
                if data.value.len() > self.config.max_value_bytes {
                    return reply(self.status(output, -1, Some(b"Data too large\0"), hint, None));
                }
                let random = match entropy.next_u64() {
                    Ok(random) => random,
                    Err(error) => {
                        return reply(self.status(
                            output,
                            -1,
                            Some(b"Randomness unavailable\0"),
                            hint,
                            Some(Fault::Entropy(error)),
                        ));
                    }
                };
                let quota = self.policy(now, self.reserved, self.config.max_put_evictions)?;
                Command::Put(
                    Put {
                        key: data.key,
                        kind: data.kind,
                        priority: data.priority,
                        anonymity: data.anonymity,
                        replication: data.replication,
                        expiration: data.expiration,
                        value: data.value,
                    },
                    PutPolicy {
                        ceiling_bytes: quota.ceiling_bytes,
                        target_bytes: quota.target_bytes,
                        now,
                        max_evictions: quota.max_evictions,
                        random,
                    },
                )
            }
            Request::Remove { key, value } => Command::Remove { key, value },
            Request::Get {
                key,
                kind,
                next_uid,
                random,
            } => {
                let selection = Selection::Get {
                    key,
                    kind,
                    next_uid,
                    random,
                };
                let bits = if random {
                    match entropy.next_u64() {
                        Ok(bits) => bits,
                        Err(error) => {
                            return reply(self.empty(output, Some(Fault::Entropy(error))));
                        }
                    }
                } else {
                    0
                };
                Command::Select(selection, bits)
            }
            Request::ZeroAnonymity { kind, next_uid } => {
                Command::Select(Selection::ZeroAnonymity { kind, next_uid }, 0)
            }
            Request::Replication => {
                let bits = match entropy.next_u64() {
                    Ok(bits) => bits,
                    Err(error) => return reply(self.empty(output, Some(Fault::Entropy(error)))),
                };
                Command::Select(Selection::Replication, bits)
            }
        };
        let serial = self.work_serial.checked_add(1).ok_or(Error::Overflow)?;
        self.work_serial = serial;
        self.work = Some(Pending {
            client: client.serial,
            kind: command.kind(),
            reply: ReplyContext { required, hint },
        });
        Ok(Dispatch::Run {
            id: WorkId {
                owner: self.owner,
                serial,
            },
            command,
        })
    }

    fn original(&self, id: &WorkId<'id>) -> Result<&Pending, Error> {
        self.work
            .as_ref()
            .filter(|_| core::ptr::eq(id.owner, self.owner) && id.serial == self.work_serial)
            .ok_or(Error::Stale)
    }

    /// Retire a command after the backend confirms cancellation before any
    /// authoritative mutation. An uncertain outcome goes through `finish`.
    pub fn cancel(&mut self, id: &WorkId<'id>) -> Result<(), Error> {
        self.original(id)?;
        self.work = None;
        Ok(())
    }

    /// Settle the original command and encode its official reply. A mismatched
    /// completion or short output leaves the original command in flight.
    pub fn finish<E: BackendError>(
        &mut self,
        id: &WorkId<'id>,
        completion: Completion<'_, E>,
        output: &mut [u8],
    ) -> Result<ReplyAction<E>, Error> {
        let original = self.original(id)?;
        if completion.kind() != original.kind {
            return Err(Error::Conflict);
        }
        if output.len() < original.reply.required {
            return Err(Error::Capacity);
        }
        let hint = original.reply.hint;
        self.work = None;
        match completion {
            Completion::Put(Ok(report)) => {
                self.record_hint(report.maintenance);
                self.status(output, 1, None, hint, None)
            }
            Completion::Remove(Ok(true)) => self.status(output, 1, None, hint, None),
            Completion::Remove(Ok(false)) => {
                self.status(output, 0, Some(b"Content not found\0"), hint, None)
            }
            Completion::Put(Err(error)) | Completion::Remove(Err(error)) => {
                self.backend_failure(error, output, Some(-1), hint)
            }
            Completion::Select(Ok(Some(record))) => {
                let meta = record.meta;
                let bytes = Response::Data(Data {
                    reservation: 0,
                    kind: meta.kind,
                    priority: meta.priority,
                    anonymity: meta.anonymity,
                    replication: meta.replication,
                    uid: meta.uid,
                    expiration: meta.expiration,
                    key: &meta.key,
                    value: record.value,
                })
                .encode(output)?;
                Ok(ReplyAction::Reply { bytes, fault: None })
            }
            Completion::Select(Ok(None)) => self.empty(output, None),
            Completion::Select(Err(error)) => self.backend_failure(error, output, None, hint),
        }
    }
}
