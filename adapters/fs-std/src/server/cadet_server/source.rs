//! Original DATASTORE GET ownership and shared readonly index resolution.
use super::super::{FailureScope, IndexResolver, ProviderFailure, Resolution, ports};
use gnunet_crypto::hash512;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error;
use gnunet_wire::official::{
    cadet::MAX_APPLICATION_MESSAGE_SIZE,
    datastore::{Data, Response},
    fs::BlockType,
    fs_cadet::REPLY_PREFIX,
};
use std::{
    fmt,
    task::{Context, Poll},
};

/// Producer-selected operation/service scope and original DATASTORE/index cause.
pub type Failure = ProviderFailure;
/// One copied public query. Its owner number belongs only to the serving host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    /// Actual requested official registry value, including ANY.
    pub block_type: BlockType,
    /// Actual original public query key.
    pub query: [u8; 64],
}
/// Original DATASTORE bytes, optionally paired with real shared-index output.
/// No type6 descriptor is ever exposed as a transferable encrypted block.
pub struct Block {
    record: OwnedFrame,
    resolved: Option<Vec<u8>>,
}
impl Block {
    /// Retain an original actual DATA record containing a transferable block.
    /// Internal type6 descriptors require the real resolver path instead.
    pub fn from_record(record: OwnedFrame) -> Result<Self, Error> {
        let Response::Data(data) = Response::decode(record.bytes())? else {
            return Err(Error::Malformed);
        };
        if data.kind == 0 || data.kind == 6 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            record,
            resolved: None,
        })
    }
    /// Exact original DATA frame, retained separately from a resolved block.
    #[must_use]
    pub const fn record(&self) -> &OwnedFrame {
        &self.record
    }
    /// Borrow original metadata with actual encrypted bytes. A type6 resolution
    /// is a real DBLOCK and retains the original descriptor's expiry and key.
    pub fn data(&self) -> Result<Data<'_>, Error> {
        let Response::Data(data) = Response::decode(self.record.bytes())? else {
            return Err(Error::Malformed);
        };
        if let Some(value) = &self.resolved {
            if data.kind != 6 {
                return Err(Error::Malformed);
            }
            Ok(Data {
                kind: 1,
                value,
                ..data
            })
        } else if data.kind == 0 || data.kind == 6 {
            Err(Error::Unsupported)
        } else {
            Ok(data)
        }
    }
}
/// One original selected record rejected without settling its source selection
/// in this observation. Invalid selection/UID metadata terminates on a later poll.
/// The exact DATA, selection and concrete cause remain owned by this observation.
/// No deletion, DATA_END, peer negative or successful resolution is inferred.
pub struct RejectedRecord {
    selection: Selection,
    record: OwnedFrame,
    cause: Failure,
}
impl RejectedRecord {
    /// Original immutable lookup selection, independent of the row metadata.
    #[must_use]
    pub const fn selection(&self) -> Selection {
        self.selection
    }
    /// Complete original actual DATA frame, preserving key/type/UID/value/expiry.
    #[must_use]
    pub const fn record(&self) -> &OwnedFrame {
        &self.record
    }
    /// Borrow the original selected row, including its real UID and key.
    pub fn data(&self) -> Result<Data<'_>, Error> {
        let Response::Data(data) = Response::decode(self.record.bytes())? else {
            return Err(Error::Malformed);
        };
        Ok(data)
    }
    /// The exact original72-byte descriptor only when this is such a type6 row.
    /// A malformed descriptor remains available unchanged through data().value.
    pub fn descriptor(&self) -> Result<Option<&[u8; 72]>, Error> {
        let data = self.data()?;
        if data.kind != 6 {
            return Ok(None);
        }
        Ok(data.value.try_into().ok())
    }
    /// Original refusal and producer-selected scope, including shared-index errors.
    #[must_use]
    pub const fn cause(&self) -> &Failure {
        &self.cause
    }
}
impl fmt::Debug for RejectedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut record = f.debug_struct("RejectedRecord");
        record.field("selection", &self.selection);
        if let Ok(data) = self.data() {
            record
                .field("uid", &data.uid)
                .field("key", &data.key)
                .field("kind", &data.kind)
                .field("value_bytes", &data.value.len());
        }
        record.field("cause", &self.cause).finish()
    }
}
/// Actual terminal observation retained after local query retirement.
/// None of these variants is an application response or remote absence proof.
pub enum Retirement {
    /// No next native GET/resolution was admitted; earlier row/terminal
    /// observations were already returned to the original owner.
    Unsubmitted,
    /// Actual original GET DATA, retained without admitting a fresh resolver.
    Data(OwnedFrame),
    /// Actual original GET DATA_END, distinct from retiring without a result.
    StorageEnd,
    /// Actual queued index resolution completed with this real block.
    Resolved(Block),
    /// Original record/resolution refusal and its exact raw row. Fatal shared
    /// index failures retain their classification even after channel retirement.
    Rejected(RejectedRecord),
    /// Original native operation or checked local refusal.
    Failed(Failure),
}
impl fmt::Debug for Retirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsubmitted => f.write_str("Unsubmitted"),
            Self::StorageEnd => f.write_str("StorageEnd"),
            Self::Data(record) => f
                .debug_struct("Data")
                .field("wire_bytes", &record.len())
                .finish(),
            Self::Resolved(block) => f
                .debug_struct("Resolved")
                .field("original_wire_bytes", &block.record().len())
                .field("block_bytes", &block.data().map(|data| data.value.len()))
                .finish(),
            Self::Rejected(record) => f.debug_tuple("Rejected").field(record).finish(),
            Self::Failed(cause) => f.debug_tuple("Failed").field(cause).finish(),
        }
    }
}
/// Retired local selection plus its actual final observation. No new GET or
/// resolution may acquire this original owner after this result.
#[derive(Debug)]
pub struct Retired {
    /// Exact original selection, independent of any later query/channel.
    pub selection: Selection,
    /// Actual terminal or unsubmitted-boundary observation.
    pub observation: Retirement,
}
impl Retired {
    /// Original actual failure, if one was observed at retirement. The caller
    /// must preserve its explicit scope even for a retired channel.
    #[must_use]
    pub fn cause(&self) -> Option<&Failure> {
        match &self.observation {
            Retirement::Rejected(record) => Some(record.cause()),
            Retirement::Failed(cause) => Some(cause),
            _ => None,
        }
    }
}
/// Original local source availability, never native connection readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Availability {
    /// Custom source reports no lifecycle information, not proof of health.
    Unreported,
    /// This local owner has not been permanently retired. Individual reads,
    /// row validation and native reconnect can still fail.
    Open,
    /// Its actual original port is permanently unavailable; supervisor action
    /// is required, and no application query may be replayed implicitly.
    Unavailable,
    /// Caller explicitly physically closed this original source owner.
    Closed,
}
/// One original serialized source observation.
pub enum Progress {
    /// Real source admission, DATASTORE IO or index-worker progress.
    Activity,
    /// Original nonterminal record refusal; the same selection remains active.
    /// Any permitted next GET is admitted only on a later poll. A checked local
    /// bound or invalid cursor instead produces a terminal error on that poll.
    Skipped(RejectedRecord),
    /// Original local selection retired after its current operation settled.
    /// This is not NotFound and never authorizes a peer reply.
    Retired(Retired),
    /// Original native dependency permanently retired; preserve its actual
    /// cause and stop serving instead of accepting endlessly failing queries.
    Unavailable {
        /// Original selection whose port observation established retirement.
        selection: Selection,
        /// Original port refusal/completion, including native uncertainty.
        cause: Failure,
    },
    /// Actual nonterminal UBLOCK from an explicitly requested source sweep.
    /// The source is paused at a safe unsubmitted UID boundary; its owner must
    /// call resume after accepting this original item, or request_retire.
    Candidate(Block),
    /// Actual terminal matching block or real on-demand resolution output.
    Found(Block),
    /// Actual DATASTORE DATA_END, not an FS wire negative or END.
    NotFound,
}
/// Explicit original read owner. There is one active query at a time; a closed
/// native channel does not cancel, replace or rebind this source operation.
pub trait BlockSource {
    /// Read only local lifecycle. Unknown never claims successful service.
    fn availability(&self) -> Availability {
        Availability::Unreported
    }
    /// Retire the current selection at its next actual operation boundary.
    /// Drain an admitted GET/resolution; stop unsubmitted continuation work and
    /// return Retired with the original observation rather than NotFound.
    fn request_retire(&mut self);
    /// Admit exactly one original selection, copying any necessary caller data.
    fn start(&mut self, selection: Selection) -> Result<(), Failure>;
    /// Explicit multi-result sweep. The default retains an ordinary one-shot
    /// source: a terminal Found does not promise further source results.
    fn start_stream(&mut self, selection: Selection) -> Result<(), Failure> {
        self.start(selection)
    }
    /// Continue only after the owner accepted the preceding actual Candidate.
    /// Refusal admits no next native GET. One-shot sources never emit Candidate.
    fn resume(&mut self) -> Result<(), Failure> {
        Err(Failure::operation(Error::Unsupported))
    }
    /// Drive actual source work. Candidate/Skipped retain the selection; only Found,
    /// NotFound, Retired, Unavailable or Err settles it. No GET is replayed.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Failure>>;
    /// Retire original read IO/jobs explicitly, preserving any native uncertainty.
    fn close(&mut self) -> Result<(), Failure>;
}
/// Source bounds in addition to the existing native DATASTORE operation policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual DATA records examined for one fallback or multi-result sweep.
    /// Exhaustion is Capacity, never a fabricated DATA_END.
    pub records: usize,
    /// Maximum transferable encrypted bytes, at most native CADET's bound.
    pub block_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            records: 64,
            block_bytes: MAX_APPLICATION_MESSAGE_SIZE - REPLY_PREFIX,
        }
    }
}
enum Active {
    Lookup {
        selection: Selection,
        cursor: u64,
        records: usize,
        started: bool,
    },
    Resolving {
        selection: Selection,
        record: OwnedFrame,
        records: usize,
        job: Resolution,
    },
    /// Actual item already returned; no next GET is admitted until resume.
    Yielded {
        selection: Selection,
        cursor: Option<u64>,
        records: usize,
    },
    /// A checked local bound reached after its original record was observed.
    Refused { selection: Selection, error: Error },
}
/// Existing official DATASTORE port plus an optional weak port into the one
/// local server index worker. This creates no Index/WAL, thread or resolver.
pub struct Datastore<S: ports::StorePort> {
    store: S,
    resolver: Option<IndexResolver>,
    limits: Limits,
    active: Option<Active>,
    retiring: bool,
    streaming: bool,
    unavailable: bool,
    closed: bool,
}
impl<S: ports::StorePort> Datastore<S> {
    /// Retain a dedicated idle original store port. A shared store must first be
    /// serialized by its owning scheduler; it cannot have two polling owners.
    pub fn new(store: S, resolver: Option<IndexResolver>, limits: Limits) -> Result<Self, Error> {
        if store.state() == ports::StoreState::Closed {
            return Err(Error::Closed);
        }
        if limits.records == 0
            || limits.block_bytes == 0
            || limits.block_bytes > MAX_APPLICATION_MESSAGE_SIZE - REPLY_PREFIX
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            store,
            resolver,
            limits,
            active: None,
            retiring: false,
            streaming: false,
            unavailable: false,
            closed: false,
        })
    }
    fn retired(&mut self, selection: Selection, observation: Retirement) -> Progress {
        self.active = None;
        self.retiring = false;
        Progress::Retired(Retired {
            selection,
            observation,
        })
    }
    fn store_failure(
        &mut self,
        selection: Selection,
        error: ports::Error,
    ) -> Result<Progress, Failure> {
        let closed = self.store.state() == ports::StoreState::Closed;
        let cause = Failure::new(
            Box::new(error),
            if closed {
                FailureScope::Service
            } else {
                FailureScope::Operation
            },
        );
        if closed {
            self.active = None;
            self.unavailable = true;
            return Ok(Progress::Unavailable { selection, cause });
        }
        if self.retiring {
            Ok(self.retired(selection, Retirement::Failed(cause)))
        } else {
            Err(cause)
        }
    }
    fn refused_record(
        &mut self,
        selection: Selection,
        record: OwnedFrame,
        reason: Error,
    ) -> Progress {
        // A malformed DATA or foreign/backwards cursor cannot authorize a new
        // UID lookup. Preserve the actual raw input before terminal refusal.
        let record = RejectedRecord {
            selection,
            record,
            cause: Failure::operation(reason),
        };
        if self.retiring {
            return self.retired(selection, Retirement::Rejected(record));
        }
        self.active = Some(Active::Refused {
            selection,
            error: reason,
        });
        Progress::Skipped(record)
    }
    fn rejected(
        &mut self,
        selection: Selection,
        records: usize,
        record: OwnedFrame,
        cause: Failure,
    ) -> Result<Progress, Failure> {
        if self.retiring {
            return Ok(self.retired(
                selection,
                Retirement::Rejected(RejectedRecord {
                    selection,
                    record,
                    cause,
                }),
            ));
        }
        let Response::Data(data) = Response::decode(record.bytes()).map_err(Failure::operation)?
        else {
            return Err(Failure::operation(Error::Malformed));
        };
        // The previous GET already terminally produced this actual DATA. No
        // second GET starts before exposing its original nonterminal cause.
        self.active = Some(if records >= self.limits.records {
            Active::Refused {
                selection,
                error: Error::Capacity,
            }
        } else if let Some(cursor) = data.uid.checked_add(1) {
            Active::Lookup {
                selection,
                cursor,
                records,
                started: false,
            }
        } else {
            Active::Refused {
                selection,
                error: Error::Overflow,
            }
        });
        Ok(Progress::Skipped(RejectedRecord {
            selection,
            record,
            cause,
        }))
    }
    fn examined(
        &mut self,
        selection: Selection,
        cursor: u64,
        records: usize,
        frame: OwnedFrame,
    ) -> Result<Progress, Failure> {
        let data = match Response::decode(frame.bytes()) {
            Ok(Response::Data(data)) => data,
            Ok(_) => return Ok(self.refused_record(selection, frame, Error::Malformed)),
            Err(reason) => return Ok(self.refused_record(selection, frame, reason)),
        };
        if *data.key != selection.query || data.uid < cursor {
            return Ok(self.refused_record(selection, frame, Error::Authentication));
        }
        if data.kind == 6 && matches!(selection.block_type.value(), 0 | 1) {
            let descriptor: [u8; 72] = match data.value.try_into() {
                Ok(descriptor) => descriptor,
                Err(_) => {
                    return self.rejected(
                        selection,
                        records,
                        frame,
                        Failure::operation(Error::Malformed),
                    );
                }
            };
            let Some(resolver) = self.resolver.as_ref() else {
                return self.rejected(
                    selection,
                    records,
                    frame,
                    Failure::operation(Error::Unsupported),
                );
            };
            let job = match resolver.resolve(selection.query, descriptor) {
                Ok(job) => job,
                Err(error) if error.is_fatal() => return Err(Failure::service(error)),
                Err(error) => {
                    return self.rejected(selection, records, frame, Failure::operation(error));
                }
            };
            self.active = Some(Active::Resolving {
                selection,
                record: frame,
                records,
                job,
            });
            return Ok(Progress::Activity);
        }
        let requested = selection.block_type.value();
        let matching =
            data.kind != 0 && data.kind != 6 && (requested == 0 || data.kind == requested);
        if matching {
            if data.value.len() > self.limits.block_bytes {
                return self.rejected(
                    selection,
                    records,
                    frame,
                    Failure::operation(Error::TooLarge),
                );
            }
            if matches!(data.kind, 1 | 2) && hash512(data.value) != selection.query {
                return self.rejected(
                    selection,
                    records,
                    frame,
                    Failure::operation(Error::Authentication),
                );
            }
            if data.kind == 9 {
                if let Err(error) = gnunet_fs::ublock::verify_envelope(data.value, &selection.query)
                {
                    return self.rejected(selection, records, frame, Failure::operation(error));
                }
            } else if !matches!(data.kind, 1 | 2) {
                return self.rejected(
                    selection,
                    records,
                    frame,
                    Failure::operation(Error::Unsupported),
                );
            }
            if self.streaming && data.kind == 9 {
                self.active = Some(Active::Yielded {
                    selection,
                    cursor: data.uid.checked_add(1),
                    records,
                });
                return Ok(Progress::Candidate(
                    Block::from_record(frame).map_err(Failure::operation)?,
                ));
            }
            return Ok(Progress::Found(
                Block::from_record(frame).map_err(Failure::operation)?,
            ));
        }
        self.rejected(
            selection,
            records,
            frame,
            Failure::operation(Error::Unsupported),
        )
    }
}
impl<S: ports::StorePort> BlockSource for Datastore<S> {
    fn availability(&self) -> Availability {
        if self.closed {
            Availability::Closed
        } else if self.unavailable || self.store.state() == ports::StoreState::Closed {
            Availability::Unavailable
        } else {
            Availability::Open
        }
    }
    fn request_retire(&mut self) {
        if self.active.is_some() {
            self.retiring = true;
        }
    }
    fn start(&mut self, selection: Selection) -> Result<(), Failure> {
        if matches!(
            self.availability(),
            Availability::Closed | Availability::Unavailable
        ) {
            return Err(Failure::service(Error::Closed));
        }
        if self.active.is_some() {
            return Err(Failure::operation(Error::Conflict));
        }
        self.retiring = false;
        self.streaming = false;
        self.active = Some(Active::Lookup {
            selection,
            cursor: 0,
            records: 0,
            started: false,
        });
        Ok(())
    }
    fn start_stream(&mut self, selection: Selection) -> Result<(), Failure> {
        self.start(selection)?;
        self.streaming = matches!(selection.block_type.value(), 0 | 9);
        Ok(())
    }
    fn resume(&mut self) -> Result<(), Failure> {
        let active = self
            .active
            .take()
            .ok_or_else(|| Failure::operation(Error::NotReady))?;
        let (selection, cursor, records) = match active {
            Active::Yielded {
                selection,
                cursor,
                records,
            } => (selection, cursor, records),
            original => {
                self.active = Some(original);
                return Err(Failure::operation(Error::Conflict));
            }
        };
        self.active = Some(if records >= self.limits.records {
            Active::Refused {
                selection,
                error: Error::Capacity,
            }
        } else if let Some(cursor) = cursor {
            Active::Lookup {
                selection,
                cursor,
                records,
                started: false,
            }
        } else {
            Active::Refused {
                selection,
                error: Error::Overflow,
            }
        });
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Failure>> {
        let Some(active) = self.active.take() else {
            return Poll::Pending;
        };
        match active {
            Active::Lookup {
                selection,
                cursor,
                records,
                started: false,
            } => {
                if self.retiring {
                    return Poll::Ready(Ok(self.retired(selection, Retirement::Unsubmitted)));
                }
                let admitted = self.store.start(ports::Lookup {
                    key: selection.query,
                    // Match the existing FS local lookup: D must see its real
                    // type6 fallback, retaining stable UID sweep semantics.
                    kind: if selection.block_type == BlockType::DBLOCK {
                        0
                    } else {
                        selection.block_type.value()
                    },
                    next_uid: cursor,
                });
                if let Err(error) = admitted {
                    return Poll::Ready(self.store_failure(selection, error));
                }
                self.active = Some(Active::Lookup {
                    selection,
                    cursor,
                    records,
                    started: true,
                });
                Poll::Ready(Ok(Progress::Activity))
            }
            Active::Lookup {
                selection,
                cursor,
                records,
                started: true,
            } => match self.store.poll(cx) {
                Poll::Pending => {
                    self.active = Some(Active::Lookup {
                        selection,
                        cursor,
                        records,
                        started: true,
                    });
                    Poll::Pending
                }
                Poll::Ready(Ok(ports::LookupProgress::Activity)) => {
                    self.active = Some(Active::Lookup {
                        selection,
                        cursor,
                        records,
                        started: true,
                    });
                    Poll::Ready(Ok(Progress::Activity))
                }
                Poll::Ready(Ok(ports::LookupProgress::Complete(Some(frame)))) => {
                    if self.retiring {
                        return Poll::Ready(Ok(self.retired(selection, Retirement::Data(frame))));
                    }
                    let records = records
                        .checked_add(1)
                        .ok_or_else(|| Failure::operation(Error::Overflow))?;
                    Poll::Ready(self.examined(selection, cursor, records, frame))
                }
                Poll::Ready(Ok(ports::LookupProgress::Complete(None))) => {
                    if self.retiring {
                        Poll::Ready(Ok(self.retired(selection, Retirement::StorageEnd)))
                    } else {
                        Poll::Ready(Ok(Progress::NotFound))
                    }
                }
                Poll::Ready(Ok(ports::LookupProgress::Removed(_))) => {
                    Poll::Ready(Err(Failure::operation(Error::Malformed)))
                }
                Poll::Ready(Err(error)) => Poll::Ready(self.store_failure(selection, error)),
            },
            Active::Resolving {
                selection,
                record,
                records,
                mut job,
            } => match job.poll(cx) {
                Poll::Pending => {
                    self.active = Some(Active::Resolving {
                        selection,
                        record,
                        records,
                        job,
                    });
                    Poll::Pending
                }
                Poll::Ready(Err(error)) if error.is_fatal() && !self.retiring => {
                    Poll::Ready(Err(Failure::service(error)))
                }
                Poll::Ready(Err(error)) => {
                    let scope = if error.is_fatal() {
                        FailureScope::Service
                    } else {
                        FailureScope::Operation
                    };
                    Poll::Ready(self.rejected(
                        selection,
                        records,
                        record,
                        Failure::new(Box::new(error), scope),
                    ))
                }
                Poll::Ready(Ok(bytes)) => {
                    if bytes.len() > self.limits.block_bytes {
                        return Poll::Ready(self.rejected(
                            selection,
                            records,
                            record,
                            Failure::operation(Error::TooLarge),
                        ));
                    }
                    if hash512(&bytes) != selection.query {
                        return Poll::Ready(self.rejected(
                            selection,
                            records,
                            record,
                            Failure::operation(Error::Authentication),
                        ));
                    }
                    let block = Block {
                        record,
                        resolved: Some(bytes),
                    };
                    if self.retiring {
                        Poll::Ready(Ok(self.retired(selection, Retirement::Resolved(block))))
                    } else {
                        Poll::Ready(Ok(Progress::Found(block)))
                    }
                }
            },
            Active::Yielded {
                selection,
                cursor,
                records,
            } => {
                if self.retiring {
                    Poll::Ready(Ok(self.retired(selection, Retirement::Unsubmitted)))
                } else {
                    self.active = Some(Active::Yielded {
                        selection,
                        cursor,
                        records,
                    });
                    Poll::Pending
                }
            }
            Active::Refused { selection, error } => {
                if self.retiring {
                    Poll::Ready(Ok(
                        self.retired(selection, Retirement::Failed(Failure::operation(error)))
                    ))
                } else {
                    Poll::Ready(Err(Failure::operation(error)))
                }
            }
        }
    }
    fn close(&mut self) -> Result<(), Failure> {
        self.closed = true;
        // Drop only this caller's readonly resolution wait. An already queued
        // index job remains on the one original worker, without a second WAL.
        self.active = None;
        self.store.close().map_err(Failure::operation)
    }
}
