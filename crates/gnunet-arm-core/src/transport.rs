//! Logical MQ epochs and aggregate queued-frame storage; no OS transport.
use crate::wire::Request;
use gnunet_types::{AbsoluteTime, Error};
/// Original ARM MQ incarnation; independent from GNUNET_CLIENT socket retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionEpoch {
    pub(crate) scope: Scope,
    pub(crate) serial: u64,
}
/// Exact local queued-frame incarnation, never encoded on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameTicket {
    scope: Scope,
    connection: ConnectionEpoch,
    serial: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Scope {
    pub epoch: u64,
    pub origin: usize,
}
/// One small caller-owned queued-frame slot. Variable bytes are in one aggregate
/// pool, independently from the maximum65535-byte individual frame width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameSlot {
    offset: usize,
    len: usize,
    serial: u64,
    used: bool,
}
impl FrameSlot {
    /// Vacant initialized metadata.
    pub const EMPTY: Self = Self {
        offset: 0,
        len: 0,
        serial: 0,
        used: false,
    };
}
pub(crate) struct Frames<'a> {
    scope: Scope,
    slots: &'a mut [FrameSlot],
    bytes: &'a mut [u8],
    tail: usize,
    next: Option<u64>,
    current: Option<FrameTicket>,
}
impl<'a> Frames<'a> {
    pub fn new(
        scope: Scope,
        slots: &'a mut [FrameSlot],
        bytes: &'a mut [u8],
    ) -> Result<Self, Error> {
        if slots.is_empty() || bytes.len() < 4 {
            return Err(Error::Capacity);
        }
        slots.fill(FrameSlot::EMPTY);
        bytes.fill(0);
        Ok(Self {
            scope,
            slots,
            bytes,
            tail: 0,
            next: Some(1),
            current: None,
        })
    }
    pub fn can_push(&self, len: usize) -> Result<(), Error> {
        if self.next.is_none() {
            return Err(Error::Capacity);
        }
        let live = self
            .slots
            .iter()
            .filter(|s| s.used)
            .try_fold(0usize, |a, s| a.checked_add(s.len).ok_or(Error::Overflow))?;
        if self.slots.iter().all(|s| s.used)
            || live.checked_add(len).is_none_or(|n| n > self.bytes.len())
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub fn push(&mut self, request: Request<'_>) -> Result<(), Error> {
        let len = request.encoded_len()?;
        self.can_push(len)?;
        let serial = self.next.ok_or(Error::Capacity)?;
        let slot = self
            .slots
            .iter()
            .position(|s| !s.used)
            .ok_or(Error::Capacity)?;
        if self
            .tail
            .checked_add(len)
            .is_none_or(|n| n > self.bytes.len())
        {
            let mut end = 0;
            let mut previous = None;
            loop {
                let found = self
                    .slots
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.used && previous.is_none_or(|old| s.serial > old))
                    .min_by_key(|(_, s)| s.serial)
                    .map(|(i, s)| (i, *s));
                let Some((i, s)) = found else {
                    break;
                };
                self.bytes.copy_within(s.offset..s.offset + s.len, end);
                self.slots[i].offset = end;
                end += s.len;
                previous = Some(s.serial);
            }
            self.tail = end;
        }
        let offset = self.tail;
        // Preflight above established the exact canonical request length and extent.
        request.encode(&mut self.bytes[offset..offset + len])?;
        self.slots[slot] = FrameSlot {
            offset,
            len,
            serial,
            used: true,
        };
        self.next = serial.checked_add(1);
        self.tail += len;
        Ok(())
    }
    pub fn take(&mut self, connection: ConnectionEpoch) -> Option<FrameTicket> {
        if let Some(t) = self.current {
            return Some(t);
        }
        let serial = self
            .slots
            .iter()
            .filter(|s| s.used)
            .map(|s| s.serial)
            .min()?;
        let t = FrameTicket {
            scope: self.scope,
            connection,
            serial,
        };
        self.current = Some(t);
        Some(t)
    }
    pub fn view(&self, t: FrameTicket, connection: ConnectionEpoch) -> Result<&[u8], Error> {
        if t.scope != self.scope || t.connection != connection || self.current != Some(t) {
            return Err(Error::StaleGeneration);
        }
        let s = self
            .slots
            .iter()
            .find(|s| s.used && s.serial == t.serial)
            .ok_or(Error::StaleGeneration)?;
        Ok(&self.bytes[s.offset..s.offset + s.len])
    }
    pub fn written(&mut self, t: FrameTicket, connection: ConnectionEpoch) -> Result<(), Error> {
        self.view(t, connection)?;
        let s = self
            .slots
            .iter_mut()
            .find(|s| s.used && s.serial == t.serial)
            .ok_or(Error::StaleGeneration)?;
        s.used = false;
        self.current = None;
        if !self.slots.iter().any(|s| s.used) {
            self.tail = 0;
        }
        Ok(())
    }
    pub fn current(&self) -> Option<FrameTicket> {
        self.current
    }
    pub fn clear(&mut self) {
        for s in &mut *self.slots {
            s.used = false;
        }
        self.tail = 0;
        self.current = None;
    }
}
pub(crate) struct Link {
    scope: Scope,
    next: Option<u64>,
    pub current: Option<ConnectionEpoch>,
    attempt: Option<ConnectionEpoch>,
    want: bool,
    pub retry: Option<AbsoluteTime>,
    pub backoff: u64,
    pub initial: bool,
    pub closed: bool,
}
impl Link {
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            next: Some(1),
            current: None,
            attempt: None,
            want: true,
            retry: None,
            backoff: 0,
            initial: true,
            closed: false,
        }
    }
    pub fn check(&self, e: ConnectionEpoch) -> Result<(), Error> {
        if !self.closed && self.current == Some(e) {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }
    pub fn take_connect(&mut self, now: AbsoluteTime) -> Result<Option<ConnectionEpoch>, Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if let Some(epoch) = self.attempt {
            return Ok(Some(epoch));
        }
        let due = self
            .retry
            .is_some_and(|d| d.as_micros() != u64::MAX && d <= now);
        if self.current.is_some() {
            if due {
                self.retry = None;
            }
            return Ok(None);
        }
        if !self.want && !due {
            return Ok(None);
        }
        let serial = self.next.ok_or(Error::Capacity)?;
        let epoch = ConnectionEpoch {
            scope: self.scope,
            serial,
        };
        self.next = serial.checked_add(1);
        self.attempt = Some(epoch);
        self.want = false;
        if due {
            self.retry = None;
        }
        Ok(Some(epoch))
    }
    pub fn can_report(&self, e: ConnectionEpoch) -> Result<(), Error> {
        if !self.closed && self.attempt == Some(e) {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }
    pub fn admitted(&mut self, e: ConnectionEpoch) -> Result<(), Error> {
        self.can_report(e)?;
        self.attempt = None;
        self.current = Some(e);
        self.initial = false;
        Ok(())
    }
    pub fn unavailable(&mut self, e: ConnectionEpoch) -> Result<bool, Error> {
        self.can_report(e)?;
        self.attempt = None;
        let initial = self.initial;
        self.initial = false;
        if initial {
            self.closed = true;
        }
        Ok(initial)
    }
    pub fn lost(&mut self, e: ConnectionEpoch, now: AbsoluteTime) -> Result<(), Error> {
        self.check(e)?;
        self.current = None;
        // add_delayed(ZERO) is placed on the scheduler's ready queue during
        // registration. A subsequent wall-clock rollback cannot suspend it.
        // relative_to_absolute at FOREVER retains FOREVER, including delay0.
        self.retry = Some(if self.backoff == 0 && now.as_micros() != u64::MAX {
            AbsoluteTime::from_micros(0)
        } else {
            AbsoluteTime::from_micros(now.as_micros().saturating_add(self.backoff))
        });
        self.backoff = self.backoff.max(1000).saturating_mul(2).min(900_000_000);
        Ok(())
    }
    pub fn connect_now(&mut self) {
        if !self.closed && self.current.is_none() {
            self.want = true;
        }
    }
    pub fn stop(&mut self) -> Option<ConnectionEpoch> {
        let old = self.current.take();
        self.attempt = None;
        self.want = false;
        self.retry = None;
        self.closed = true;
        old
    }
}
