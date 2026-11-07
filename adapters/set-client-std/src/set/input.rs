//! Original write/result/iteration/cookie consumption, without inferred ACKs.
use super::*;
use crate::{ElementOwned, Epoch, Status};
use gnunet_wire::official::set::ClientResponse;
impl Set {
    pub(super) fn written(
        &mut self,
        epoch: Epoch,
        tag: Option<Tag>,
        bytes: usize,
        complete: bool,
    ) -> Result<SetProgress, Error> {
        let Some(tag) = tag else {
            if complete {
                self.copy_connect = None;
            }
            return Ok(SetProgress::InitializerWritten {
                epoch,
                bytes,
                complete,
            });
        };
        match tag {
            Tag::Mutation(serial) => {
                let at = self
                    .mutations
                    .iter()
                    .position(|r| r.id.serial == serial)
                    .ok_or(Fault::Stale)?;
                let r = &mut self.mutations[at];
                r.written = r.written.checked_add(bytes).ok_or(Fault::Overflow)?;
                r.whole = complete;
                if complete {
                    Ok(SetProgress::MutationWritten(self.mutations.remove(at)))
                } else {
                    Ok(SetProgress::Activity)
                }
            }
            Tag::Operation(rid) => {
                let row = self
                    .operations
                    .iter_mut()
                    .find(|r| r.request_id == rid)
                    .ok_or(Fault::Stale)?;
                row.written = row.written.checked_add(bytes).ok_or(Fault::Overflow)?;
                row.request_written = complete;
                if complete {
                    row.acceptance = None;
                }
                Ok(SetProgress::OperationWritten {
                    operation: row.id.clone(),
                    bytes,
                    complete,
                })
            }
            Tag::Cancel(rid) => {
                let at = self
                    .operations
                    .iter()
                    .position(|r| r.request_id == rid)
                    .ok_or(Fault::Stale)?;
                if complete {
                    let mut r = self.operations.remove(at);
                    r.cancellation_written = true;
                    Ok(SetProgress::OperationCancelled(r))
                } else {
                    Ok(SetProgress::Activity)
                }
            }
            Tag::Iterate(serial) => {
                let row = self
                    .iteration
                    .as_mut()
                    .filter(|r| r.id.serial == serial)
                    .ok_or(Fault::Stale)?;
                row.written = row.written.checked_add(bytes).ok_or(Fault::Overflow)?;
                row.request_written = complete;
                Ok(SetProgress::Activity)
            }
            Tag::IterAck(serial, more) => {
                let row = self
                    .iteration
                    .as_mut()
                    .filter(|r| r.id.serial == serial)
                    .ok_or(Fault::Stale)?;
                if row.ack_pending != Some(more) {
                    return Err(Fault::Stale.into());
                }
                if !complete {
                    return Ok(SetProgress::Activity);
                }
                row.ack_pending = None;
                if more {
                    Ok(SetProgress::Activity)
                } else {
                    row.stop_written = true;
                    self.generation = self.generation.checked_add(1).ok_or(Fault::Overflow)?;
                    Ok(SetProgress::IterationCancelled(
                        *self.iteration.take().ok_or(Fault::Stale)?,
                    ))
                }
            }
            Tag::Copy(serial) => {
                let row = self
                    .copy
                    .as_mut()
                    .filter(|r| r.id.serial == serial)
                    .ok_or(Fault::Stale)?;
                row.written = row.written.checked_add(bytes).ok_or(Fault::Overflow)?;
                row.request_written = complete;
                Ok(SetProgress::Activity)
            }
        }
    }
    pub(super) fn frame(&mut self, epoch: Epoch, bytes: &[u8]) -> Result<SetProgress, Error> {
        match ClientResponse::decode(bytes, self.limits.abi)? {
            ClientResponse::Result {
                current_size,
                request_id,
                status,
                element,
            } => {
                let Some(at) = self
                    .operations
                    .iter()
                    .position(|r| r.request_id == request_id)
                else {
                    return Ok(SetProgress::StaleResult { request_id });
                };
                let row = &self.operations[at];
                if row.cancellation.is_some() {
                    return Ok(SetProgress::StaleResult { request_id });
                }
                if !row.request_written {
                    return Err(Fault::Malformed.into());
                }
                let status = Status::from_raw(status)?;
                let element = ElementOwned::copy(element)?;
                let row = &mut self.operations[at];
                row.current_size = Some(current_size);
                row.half_done |= status == Status::HalfDone;
                let operation = row.id.clone();
                let terminal = if status.terminal() {
                    Some(self.operations.remove(at))
                } else {
                    None
                };
                Ok(SetProgress::Result {
                    operation,
                    epoch,
                    current_size,
                    status,
                    element,
                    terminal,
                })
            }
            ClientResponse::IterElement {
                iteration_id,
                element,
            } => {
                let row = self.iteration.as_ref().ok_or(Fault::Malformed)?;
                if row.generation != iteration_id
                    || !row.request_written
                    || row.awaiting_ack
                    || row.ack_pending.is_some()
                {
                    return Err(Fault::Malformed.into());
                }
                let id = row.id.clone();
                if row.cancellation.is_some() {
                    self.iteration.as_mut().ok_or(Fault::Stale)?.awaiting_ack = true;
                    self.iteration_continue(&id, false)?;
                    return Ok(SetProgress::Activity);
                }
                let element = ElementOwned::copy(element)?;
                let row = self.iteration.as_mut().ok_or(Fault::Stale)?;
                row.elements = row.elements.checked_add(1).ok_or(Fault::Overflow)?;
                row.awaiting_ack = true;
                Ok(SetProgress::IterElement {
                    iteration: id,
                    element,
                })
            }
            ClientResponse::IterDone => {
                let Some(row) = self.iteration.as_ref() else {
                    return Ok(SetProgress::Activity);
                };
                if !row.request_written || row.awaiting_ack || row.ack_pending.is_some() {
                    return Err(Fault::Malformed.into());
                }
                self.generation = self.generation.checked_add(1).ok_or(Fault::Overflow)?;
                let receipt = self.iteration.take().ok_or(Fault::Stale)?;
                if receipt.cancellation.is_some() {
                    Ok(SetProgress::IterationCancelled(*receipt))
                } else {
                    Ok(SetProgress::IterDone(*receipt))
                }
            }
            ClientResponse::CopyLazy { cookie } => {
                if !self.copy.as_ref().is_some_and(|r| r.request_written) {
                    return Err(Fault::Malformed.into());
                }
                let request = self.copy.take().ok_or(Fault::Stale)?;
                let ticket = CopyTicket {
                    domain: self.domain.clone(),
                    epoch,
                    operation: self.operation,
                    cookie,
                };
                Ok(SetProgress::CopyReady { request, ticket })
            }
            ClientResponse::Request { .. } => Err(Fault::Malformed.into()),
        }
    }
}
