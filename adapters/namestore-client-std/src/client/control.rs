//! One retained immutable NEXT/STOP control and exact whole-write credit.
use super::{Client, ControlState, Mode, Origin, StreamMeta};
use crate::{
    Control, ControlKind, EndpointSource, Epoch, Error, Instance, Kind, Limits, LocalReason,
    Operation, Progress, SecretKey, ipc,
};
use gnunet_service_runtime::framing::{Class, OwnedFrame};
use gnunet_types::Error as Fault;
use std::time::Duration;
use tokio::time::Instant;
use zeroize::Zeroizing;
impl<'id> Client<'id> {
    pub(crate) fn stream_new(
        instance: &'id Instance,
        source: EndpointSource,
        zone: Option<&SecretKey>,
        filter: u16,
        monitor: Option<bool>,
        until: u64,
        mut limits: Limits,
    ) -> Result<(Self, Operation<'id>), Error> {
        limits.operations = 1;
        limits.reconnect = false;
        let mut this = Self::new(instance, source, limits)?;
        let key = zone.map(SecretKey::view).transpose()?;
        let request = if monitor.is_some() {
            ipc::Request::MonitorStart {
                zone: key,
                iterate_first: u32::from(monitor.unwrap_or(false)),
                filter,
            }
        } else {
            ipc::Request::IterateStart {
                rid: this.rid()?,
                zone: key,
                filter,
            }
        };
        let op = this.append(
            request,
            if monitor.is_some() {
                Kind::Monitor
            } else {
                Kind::Iterator
            },
            zone.map(SecretKey::try_clone_secret),
            until,
        )?;
        this.mode = if monitor.is_some() {
            Mode::Monitor
        } else {
            Mode::Iterator
        };
        this.stream = Some(StreamMeta {
            operation: op,
            credit: 0,
            synced: false,
            stopping: false,
        });
        Ok((this, op))
    }
    pub(crate) fn take_control_close(&mut self) -> Option<crate::Loss<'id>> {
        self.control_close.take()
    }
    pub(crate) fn credit(&self) -> u64 {
        if self.closed || self.epoch.is_none() {
            return 0;
        }
        self.stream.as_ref().map_or(0, |s| s.credit)
    }
    pub(crate) fn synchronized(&self) -> bool {
        !self.closed && self.epoch.is_some() && self.stream.as_ref().is_some_and(|s| s.synced)
    }
    fn stream_control(&mut self, kind: ControlKind, until: u64) -> Result<Control<'id>, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.blocked || self.paused || self.admission_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        if self.control.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        let stream = self.stream.as_ref().ok_or(Fault::Unsupported)?;
        if stream.stopping {
            return Err(Fault::Closed.into());
        }
        let operation = stream.operation;
        let credit = stream.credit;
        if let ControlKind::Next { limit } = kind {
            if limit == 0 {
                return Err(Fault::InvalidInput.into());
            }
            if credit.checked_add(limit).ok_or(Fault::Overflow)? > self.limits.credit {
                return Err(Fault::Capacity.into());
            }
        }
        let row = self.index(operation)?;
        let original = self.slots[row].as_ref().ok_or(Fault::StaleGeneration)?;
        if original.outcome.is_some() || original.reason.is_some() {
            return Err(Fault::NotReady.into());
        }
        if matches!(kind, ControlKind::Next { .. }) && !original.written {
            return Err(Fault::NotReady.into());
        }
        let rid = original.rid;
        let until = until.min(original.expires);
        let original_hard = original.hard;
        let now = self.admission_now()?;
        if until <= now || until == u64::MAX {
            return Err(Fault::Deadline.into());
        }
        let hard = Instant::now()
            .checked_add(Duration::from_micros(until - now))
            .ok_or(Fault::Overflow)?
            .min(original_hard);
        let request = match (self.mode, kind) {
            (Mode::Iterator, ControlKind::Next { limit }) => {
                ipc::Request::IterateNext { rid, limit }
            }
            (Mode::Iterator, ControlKind::Stop) => ipc::Request::IterateStop { rid },
            (Mode::Monitor, ControlKind::Next { limit }) => {
                ipc::Request::MonitorNext { limit, reserved: 0 }
            }
            _ => return Err(Fault::Unsupported.into()),
        };
        let len = request.encoded_len()?;
        let total = self.bytes.checked_add(len).ok_or(Fault::Overflow)?;
        if len > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        if total > self.limits.source_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut frame = Zeroizing::new(Vec::new());
        frame.try_reserve_exact(len).map_err(|_| Fault::Capacity)?;
        frame.resize(len, 0);
        request.encode(&mut frame)?;
        let id = self.scope.control()?;
        self.control = Some(ControlState {
            id,
            kind,
            source: Some(OwnedFrame::new(std::mem::take(&mut *frame))),
            len,
            sent: 0,
            queued: false,
            epoch: None,
            expires: until,
            hard,
        });
        self.bytes = total;
        if kind == ControlKind::Stop {
            self.stream.as_mut().ok_or(Fault::Conflict)?.stopping = true;
        }
        Ok(id)
    }
    pub(crate) fn stream_next(&mut self, limit: u64, until: u64) -> Result<Control<'id>, Error> {
        self.stream_control(ControlKind::Next { limit }, until)
    }
    pub(crate) fn stream_stop(&mut self, until: u64) -> Result<Option<Control<'id>>, Error> {
        if self.mode != Mode::Iterator {
            return Err(Fault::Unsupported.into());
        }
        if self.control.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        let operation = self.stream.as_ref().ok_or(Fault::NotReady)?.operation;
        let row = self.index(operation)?;
        if self.slots[row].as_ref().is_some_and(|s| s.sent == 0) {
            self.retire_request(row, LocalReason::Cancelled)?;
            let _loss = self.close();
            return Ok(None);
        }
        self.stream_control(ControlKind::Stop, until).map(Some)
    }
    pub(super) fn prepare_control(
        &mut self,
        epoch: Epoch<'id>,
    ) -> Result<Option<Progress<'id>>, Error> {
        let Some(control) = self.control.as_ref() else {
            return Ok(None);
        };
        if control.queued {
            return Ok(None);
        }
        let operation = self.stream.as_ref().ok_or(Fault::Conflict)?.operation;
        let row = self.index(operation)?;
        if !self.slots[row]
            .as_ref()
            .is_some_and(|s| s.written && s.outcome.is_none())
        {
            return Ok(None);
        }
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        if framed.queued_frames() != 0 {
            return Ok(None);
        }
        let c = self.control.as_mut().ok_or(Fault::Conflict)?;
        framed.reserve(c.len, Class::Ordinary)?;
        let frame = c.source.take().ok_or(Fault::Conflict)?;
        if let Err(rejected) = framed.enqueue_owned(
            frame,
            Origin::Control {
                epoch,
                control: c.id,
            },
            Class::Ordinary,
        ) {
            c.source = Some(rejected.value.0);
            return Err(rejected.reason.into());
        }
        c.queued = true;
        c.epoch = Some(epoch);
        Ok(Some(Progress::ControlQueued {
            epoch,
            control: c.id,
            kind: c.kind,
        }))
    }
}
