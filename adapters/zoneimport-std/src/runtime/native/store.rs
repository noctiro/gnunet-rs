//! Original NAMESTORE operations and dedicated cache cursor ownership.
use super::*;
use crate::{Exposure, LocalOutcome, SourceFailure};
use gnunet_gnsrecord::RecordData;
fn records(
    input: namestore::ipc::Records<'_>,
    maximum: usize,
) -> Result<Vec<RecordData<'_>>, Error> {
    if usize::from(input.count()) > maximum {
        return Err(Fault::Capacity.into());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(usize::from(input.count()))
        .map_err(|_| Fault::Capacity)?;
    for record in input.records().iter() {
        output.push(record?);
    }
    Ok(output)
}
fn exposure(input: namestore::Submission) -> Exposure {
    match input {
        namestore::Submission::Unsent => Exposure::Unsent,
        namestore::Submission::Partial { bytes, total } => Exposure::Partial { bytes, total },
        namestore::Submission::Written { bytes } => Exposure::Whole { bytes },
    }
}
impl<'id> Runtime<'id> {
    pub(super) fn poll_ns(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<bool, Error> {
        if self.namestore_closed {
            return Ok(false);
        }
        let Some(client) = &mut self.namestore else {
            return Ok(false);
        };
        match client.poll(cx, None) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Ready(Ok(event)) => {
                self.ns_event(event, observe)?;
                Ok(true)
            }
        }
    }
    pub(super) fn ns_event(
        &mut self,
        event: namestore::Progress<'id>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        match event {
            namestore::Progress::Queued {
                epoch, operation, ..
            } => self.ns_attached(operation, epoch, false)?,
            namestore::Progress::Written {
                epoch, operation, ..
            } => {
                self.ns_attached(operation, epoch, true)?;
                if !self.closing {
                    self.resume_deferred()?;
                }
            }
            namestore::Progress::Completed(completion) => self.ns_completed(completion, observe)?,
            namestore::Progress::Lost { report, cause } => {
                let retry = self.limits.namestore.reconnect
                    && matches!(
                        &cause,
                        namestore::LossCause::Eof
                            | namestore::LossCause::Io(_)
                            | namestore::LossCause::RetirementDeadline
                    );
                self.ns_loss(report);
                self.source_error(SourceFailure::Namestore(cause));
                if !self.closing && !retry {
                    return Err(Fault::Closed.into());
                }
            }
            namestore::Progress::ConnectRetry { error, .. } => self.note_io(None, error, observe),
            namestore::Progress::Unavailable(error) => return Err(error.into()),
            namestore::Progress::Closed => self.namestore_closed = true,
            namestore::Progress::Record { .. }
            | namestore::Progress::Synchronized { .. }
            | namestore::Progress::ControlQueued { .. }
            | namestore::Progress::ControlWritten { .. } => return Err(Fault::Conflict.into()),
            _ => {}
        }
        Ok(())
    }
    fn ns_attached(
        &mut self,
        operation: namestore::Operation<'id>,
        epoch: namestore::Epoch<'id>,
        written: bool,
    ) -> Result<(), Error> {
        let row = self
            .pending
            .iter_mut()
            .flatten()
            .find(|row| match &row.native {
                Native::Check {
                    operation: original,
                    ..
                }
                | Native::Delegate {
                    operation: original,
                }
                | Native::Store {
                    operation: original,
                    ..
                } => *original == operation,
                _ => false,
            })
            .ok_or(Fault::StaleGeneration)?;
        if row
            .epoch
            .is_some_and(|original| original != epoch.diagnostic())
        {
            return Err(Fault::StaleGeneration.into());
        }
        row.epoch = Some(epoch.diagnostic());
        if written {
            row.written = true;
            row.exposure = Exposure::Whole {
                bytes: row.wire_bytes,
            };
        }
        Ok(())
    }
    fn ns_completed(
        &mut self,
        completion: namestore::Completion<'id>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let index = self
            .pending
            .iter()
            .position(|slot| {
                slot.as_ref().is_some_and(|row| match &row.native {
                    Native::Check { operation, .. }
                    | Native::Delegate { operation }
                    | Native::Store { operation, .. } => *operation == completion.operation,
                    _ => false,
                })
            })
            .ok_or(Fault::StaleGeneration)?;
        let mut row = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
        let actual = completion.epoch.map(|epoch| epoch.diagnostic());
        let outcome = (|| -> Result<(_, Option<u32>), Error> {
            if row.epoch.is_some_and(|epoch| Some(epoch) != actual) {
                return Err(Fault::StaleGeneration.into());
            }
            row.epoch = actual;
            match completion.outcome {
                namestore::Outcome::Reply(reply) => match (&row.native, reply.view()?) {
                    (
                        Native::Check {
                            label: original, ..
                        },
                        namestore::ipc::Response::Lookup {
                            label,
                            found,
                            records: set,
                            ..
                        },
                    ) => {
                        if label.bytes() != original {
                            return Err(Fault::Malformed.into());
                        }
                        if self.closing {
                            return Ok((self.core.delegation_failed(&row.job), None));
                        }
                        if found < 0 {
                            self.local_outcome(LocalOutcome::Lookup {
                                job: row.job.diagnostic(),
                                found,
                            });
                            observe(Event::ReadFailed {
                                job: row.job.diagnostic(),
                                reason: core::ReadFailure::Source,
                            });
                            return Ok((self.core.delegation_failed(&row.job), None));
                        }
                        if found > 1 || found == 0 && set.count() != 0 {
                            return Err(Fault::Malformed.into());
                        }
                        let values = records(set, self.core.limits().records_per_set)?;
                        let now = self.clock.sample()?;
                        self.last = now;
                        // Only this actual complete lookup may let Core choose
                        // no-op or the separately tracked parent replacement.
                        Ok((self.core.delegation_observed(&row.job, &values, now), None))
                    }
                    (Native::Delegate { .. }, namestore::ipc::Response::Generic { code, .. }) => {
                        Ok((
                            self.core
                                .delegated(&row.job, core::Mutation::KnownCode(code)),
                            Some(code),
                        ))
                    }
                    (
                        Native::Store { answer, .. },
                        namestore::ipc::Response::Generic { code, .. },
                    ) => {
                        if !self
                            .answers
                            .iter()
                            .flatten()
                            .any(|payload| &payload.id == answer)
                        {
                            return Err(Fault::StaleGeneration.into());
                        }
                        self.metrics.stored(row.started);
                        Ok((
                            self.core.stored(&row.job, core::Mutation::KnownCode(code)),
                            Some(code),
                        ))
                    }
                    _ => Err(Fault::Malformed.into()),
                },
                namestore::Outcome::Local { reason, submission } => {
                    row.exposure = exposure(submission);
                    self.local_outcome(LocalOutcome::Namestore {
                        job: row.job.diagnostic(),
                        reason,
                        submission,
                    });
                    observe(Event::ReadFailed {
                        job: row.job.diagnostic(),
                        reason: if reason == namestore::LocalReason::Deadline {
                            core::ReadFailure::Deadline
                        } else {
                            core::ReadFailure::Source
                        },
                    });
                    let zero = matches!(submission, namestore::Submission::Unsent);
                    if row.retiring {
                        let mutation = matches!(row.kind, Kind::Delegate | Kind::Store);
                        return Ok((
                            self.core.retired(
                                &row.job,
                                if zero || !mutation {
                                    core::Retirement::Unsent
                                } else {
                                    core::Retirement::Unknown
                                },
                            ),
                            None,
                        ));
                    }
                    let result = match row.kind {
                        Kind::CheckDelegation => self.core.delegation_failed(&row.job),
                        Kind::Delegate => self.core.delegated(
                            &row.job,
                            if zero {
                                core::Mutation::Unsent
                            } else {
                                core::Mutation::Unknown
                            },
                        ),
                        Kind::Store => self.core.stored(
                            &row.job,
                            if zero {
                                core::Mutation::Unsent
                            } else {
                                core::Mutation::Unknown
                            },
                        ),
                        _ => return Err(Fault::Conflict.into()),
                    };
                    Ok((result, None))
                }
            }
        })();
        match outcome {
            Ok((result, code)) => {
                observe(Event::Result {
                    job: row.job.diagnostic(),
                    kind: row.kind,
                    code,
                });
                self.finish_row(index, row, result)
            }
            Err(error) => {
                row.native = Native::Settled;
                self.pending[index] = Some(row);
                self.stalled = true;
                Err(error)
            }
        }
    }
    pub(super) fn poll_scans(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<bool, Error> {
        for offset in 0..self.pending.len() {
            let index = (self.cursor + offset) % self.pending.len();
            let event = match self.pending[index].as_mut().map(|row| &mut row.native) {
                Some(Native::Scan(scan)) => scan.iterator.poll(cx, None),
                _ => continue,
            };
            match event {
                Poll::Pending => {}
                Poll::Ready(Ok(event)) => {
                    self.cursor = (index + 1) % self.pending.len();
                    self.scan_event(index, event, observe)?;
                    return Ok(true);
                }
                Poll::Ready(Err(error)) => {
                    self.source_error(SourceFailure::Iterator(namestore::LossCause::Ports(error)));
                    self.scan_failed(index, observe)?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    pub(super) fn scan_failed(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let mut row = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
        let Native::Scan(scan) = &mut row.native else {
            self.pending[index] = Some(row);
            return Err(Fault::Conflict.into());
        };
        let _actual = scan.iterator.close();
        self.scan_closed(scan);
        observe(Event::ReadFailed {
            job: row.job.diagnostic(),
            reason: core::ReadFailure::Source,
        });
        let result = if row.retiring {
            self.core.retired(&row.job, core::Retirement::Unsent)
        } else {
            self.core.cache_end(&row.job, core::ReadEnd::Failed)
        };
        self.finish_row(index, row, result)
    }
    pub(super) fn scan_event(
        &mut self,
        index: usize,
        event: namestore::Progress<'id>,
        observe: &mut impl FnMut(Event<'_>),
    ) -> Result<(), Error> {
        let mut row = self.pending[index].take().ok_or(Fault::StaleGeneration)?;
        let can_next = matches!(
            &event,
            namestore::Progress::Written { .. }
                | namestore::Progress::Record { .. }
                | namestore::Progress::ControlWritten { .. }
        );
        let result = (|| -> Result<Option<Result<core::Completion, Fault>>, Error> {
            let Native::Scan(scan) = &mut row.native else {
                return Err(Fault::Conflict.into());
            };
            match event {
                namestore::Progress::Queued {
                    epoch, operation, ..
                }
                | namestore::Progress::Written {
                    epoch, operation, ..
                } => {
                    if operation != scan.iterator.operation()
                        || row.epoch.is_some_and(|value| value != epoch.diagnostic())
                    {
                        return Err(Fault::StaleGeneration.into());
                    }
                    row.epoch = Some(epoch.diagnostic());
                }
                namestore::Progress::Record {
                    epoch,
                    operation,
                    reply,
                } => {
                    if operation != scan.iterator.operation()
                        || row.epoch != Some(epoch.diagnostic())
                    {
                        return Err(Fault::StaleGeneration.into());
                    }
                    if !self.closing && !row.retiring {
                        let namestore::ipc::Response::Records {
                            label,
                            records: set,
                            ..
                        } = reply.view()?
                        else {
                            return Err(Fault::Malformed.into());
                        };
                        let label = match self.names.inventory(label.bytes()) {
                            Ok(label) if !label.contains('.') => Some(label),
                            Ok(_) | Err(Error::InvalidName(_)) => None,
                            Err(error) => return Err(error),
                        };
                        if let Some(label) = label {
                            let values = records(set, self.core.limits().records_per_set)?;
                            self.last = self.clock.sample()?;
                            self.core
                                .cache_record(&row.job, &label, &values, self.last)?;
                        }
                    }
                }
                namestore::Progress::ControlWritten { .. } => scan.next_pending = false,
                namestore::Progress::Completed(completion) => {
                    if completion.operation != scan.iterator.operation()
                        || row.epoch.is_some_and(|epoch| {
                            completion.epoch.map(|actual| actual.diagnostic()) != Some(epoch)
                        })
                    {
                        return Err(Fault::StaleGeneration.into());
                    }
                    self.scan_closed(scan);
                    let complete = match completion.outcome {
                        namestore::Outcome::Reply(reply) => {
                            matches!(reply.view()?, namestore::ipc::Response::End { .. })
                        }
                        namestore::Outcome::Local { submission, .. } => {
                            row.exposure = exposure(submission);
                            false
                        }
                    };
                    return Ok(Some(if row.retiring {
                        self.core.retired(&row.job, core::Retirement::Unsent)
                    } else {
                        self.core.cache_end(
                            &row.job,
                            if complete {
                                core::ReadEnd::Complete
                            } else {
                                core::ReadEnd::Failed
                            },
                        )
                    }));
                }
                namestore::Progress::Lost { cause, .. } => {
                    self.source_error(SourceFailure::Iterator(cause));
                    let _actual = scan.iterator.close();
                    self.scan_closed(scan);
                    return Ok(Some(if row.retiring {
                        self.core.retired(&row.job, core::Retirement::Unsent)
                    } else {
                        self.core.cache_end(&row.job, core::ReadEnd::Failed)
                    }));
                }
                namestore::Progress::ConnectRetry { error, .. } => {
                    self.note_io(None, error, observe)
                }
                namestore::Progress::Unavailable(error) => {
                    self.source_error(SourceFailure::Iterator(namestore::LossCause::Ports(error)));
                    let _actual = scan.iterator.close();
                    self.scan_closed(scan);
                    return Ok(Some(if row.retiring {
                        self.core.retired(&row.job, core::Retirement::Unsent)
                    } else {
                        self.core.cache_end(&row.job, core::ReadEnd::Failed)
                    }));
                }
                namestore::Progress::Closed => {
                    self.scan_closed(scan);
                    return Ok(Some(if row.retiring {
                        self.core.retired(&row.job, core::Retirement::Unsent)
                    } else {
                        self.core.cache_end(&row.job, core::ReadEnd::Failed)
                    }));
                }
                _ => {}
            }
            if can_next
                && !self.closing
                && !row.expired
                && !row.retiring
                && row.epoch.is_some()
                && scan.iterator.credit() == 0
                && !scan.next_pending
            {
                row.budget.check(&self.clock)?;
                let _actual = scan
                    .iterator
                    .next(self.limits.namestore.credit, row.budget.until)?;
                scan.next_pending = true;
            }
            Ok(None)
        })();
        match result {
            Ok(Some(result)) => self.finish_row(index, row, result),
            Ok(None) => {
                self.pending[index] = Some(row);
                Ok(())
            }
            Err(error) => {
                // No next poll may reinterpret the already observed frame. The
                // enclosing fatal path physically closes this retained cursor.
                if let Native::Scan(scan) = &mut row.native {
                    let _actual = scan.iterator.close();
                    self.scan_closed(scan);
                }
                if matches!(error, Error::Core(Fault::Deadline)) {
                    observe(Event::ReadFailed {
                        job: row.job.diagnostic(),
                        reason: core::ReadFailure::Deadline,
                    });
                    let result = if row.retiring {
                        self.core.retired(&row.job, core::Retirement::Unsent)
                    } else {
                        self.core.cache_end(&row.job, core::ReadEnd::Failed)
                    };
                    self.finish_row(index, row, result)
                } else {
                    self.pending[index] = Some(row);
                    Err(error)
                }
            }
        }
    }
}
