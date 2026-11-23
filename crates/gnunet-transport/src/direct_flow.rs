//! Allocation-free FLOW for one reliable direct carrier.
//!
//! The embedding owns that carrier, its validation lease and delivery to
//! CORE. It retains the original receive buffer through `Delivery` and
//! submits FLOW controls independently of ordinary payload credit.
use crate::{
    communicator::MAX_INCOMING_MESSAGE_LEN,
    flow_timing::{KEEPALIVE_MICROS as FLOW_KEEPALIVE_MICROS, MIN_MICROS as FLOW_MIN_MICROS},
    p2p::{DEFAULT_WINDOW, Flow},
};
use core::{num::NonZeroU16, num::NonZeroU64, ptr};
use gnunet_types::{Error, MonoInstant, Rejected};
use gnunet_wire::official::{Frame, HEADER_LEN, message_type as mt};

/// Largest direct payload that fits the official C incoming IPC envelope.
pub const MAX_PAYLOAD: u16 = MAX_INCOMING_MESSAGE_LEN as u16;

/// Caller storage branding admissions for one original carrier.
#[derive(Debug, Default)]
pub struct Scope {
    _byte: u8,
}

impl Scope {
    /// Create independent storage without allocation or global state.
    #[must_use]
    pub const fn new() -> Self {
        Self { _byte: 0 }
    }
}

/// The original accepted inbound payload charge.
///
/// The caller keeps this receipt with its original payload. Dropping it
/// leaves the charge in place until the carrier is retired.
#[derive(Debug)]
#[must_use]
pub struct Delivery<'scope> {
    scope: &'scope Scope,
}

#[derive(Debug)]
struct Remote {
    sequence: u32,
    sender_time: u64,
    sent_bytes: u64,
    rtt: u64,
}

#[derive(Debug)]
struct Announcement {
    sent_at: MonoInstant,
    sender_time: NonZeroU64,
    window: u64,
}

/// Observations from the same original byte-window owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    /// Configured receive-window budget.
    pub receive_capacity: u64,
    /// Original inbound charge still held by the consumer.
    pub inbound_held: u64,
    /// Latest grant actually submitted to the remote peer.
    pub inbound_window: u64,
    /// Count of original admitted inbound bytes.
    pub inbound_used: u64,
    /// Difference between the last peer-reported sent count and inbound use.
    pub inbound_loss: i64,
    /// Current peer grant and cumulative outbound charge.
    pub outbound_window: u64,
    /// Count of original admitted outbound bytes.
    pub outbound_used: u64,
    /// Remote FLOW RTT, with FOREVER representing unknown.
    pub peer_rtt: u64,
    /// Elapsed instant of the latest admitted FLOW announcement.
    pub last_announcement: Option<MonoInstant>,
}

/// The byte-window and announcement owner for one original reliable carrier.
#[derive(Debug)]
pub struct DirectFlow<'scope> {
    scope: &'scope Scope,
    max_payload: u64,
    outstanding: Option<u64>,
    inbound_window: u64,
    inbound_used: u64,
    outbound_window: u64,
    outbound_used: u64,
    remote: Option<Remote>,
    local_sequence: u32,
    announcement: Option<Announcement>,
    retry_at: MonoInstant,
    dirty: bool,
    closed: bool,
}

impl<'scope> DirectFlow<'scope> {
    /// Create one link with the official initial 128 KiB byte window.
    ///
    /// `max_payload` is the caller's actual capacity for one complete payload.
    /// FLOW controls have a separate 60-byte admission path.
    ///
    /// # Errors
    /// Rejects a payload limit outside the official direct-message extent.
    pub fn new(scope: &'scope mut Scope, max_payload: NonZeroU16) -> Result<Self, Error> {
        if !(HEADER_LEN as u16..=MAX_PAYLOAD).contains(&max_payload.get()) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            scope,
            max_payload: u64::from(max_payload.get()),
            outstanding: None,
            inbound_window: DEFAULT_WINDOW,
            inbound_used: 0,
            outbound_window: DEFAULT_WINDOW,
            outbound_used: 0,
            remote: None,
            local_sequence: 0,
            announcement: None,
            retry_at: MonoInstant(0),
            dirty: true,
            closed: false,
        })
    }

    /// Apply one FLOW control from the original authenticated carrier.
    ///
    /// A lower remote sequence with a non-stale timestamp resets the local
    /// send debit. The peer's sent count reanchors the offered window while
    /// the original outstanding payload remains charged.
    ///
    /// # Errors
    /// Rejects malformed, stale and overflowing updates without changing credit.
    pub fn receive_flow(&mut self, input: &[u8]) -> Result<(), Error> {
        self.require_live()?;
        let update = Flow::decode(input)?;
        if self
            .remote
            .as_ref()
            .is_some_and(|remote| update.sender_time < remote.sender_time)
        {
            return Err(Error::Replay);
        }
        let incoming = DEFAULT_WINDOW
            .checked_add(update.outbound_sent)
            .ok_or(Error::Overflow)?;
        incoming
            .checked_add(self.outstanding.unwrap_or(0))
            .ok_or(Error::Overflow)?;

        let restarted = self
            .remote
            .as_ref()
            .is_some_and(|remote| update.sequence < remote.sequence);
        self.dirty |=
            update.inbound_window != self.outbound_window || update.outbound_window != incoming;
        self.inbound_window = incoming;
        self.outbound_window = update.inbound_window;
        self.remote = Some(Remote {
            sequence: update.sequence,
            sender_time: update.sender_time,
            sent_bytes: update.outbound_sent,
            rtt: update.rtt,
        });
        if restarted {
            self.outbound_used = 0;
        }
        Ok(())
    }

    /// Debit the complete payload only upon successful BOX admission.
    ///
    /// The admission callback submits exactly these bytes on the original
    /// carrier. Success commits their debit until a remote sequence restart
    /// or carrier retirement. An error must mean the BOX did not enter
    /// the ordered cipher stream.
    ///
    /// # Errors
    /// Refuses an unavailable byte window, conflicting frame extent or
    /// ordinary submission failure.
    pub fn send_payload<T>(
        &mut self,
        input: &[u8],
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let size = self.payload_size(input)?;
        self.send_charged_frame(input, size, admit)
    }

    pub(crate) fn send_fragment<T>(
        &mut self,
        encoded: &[u8],
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.require_live()?;
        self.send_charged_frame(encoded, encoded.len() as u64, admit)
    }

    pub(crate) fn send_classified<T>(
        &mut self,
        input: &[u8],
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let size = self.check_extent(input.len())?;
        self.send_charged_frame(input, size, admit)
    }

    fn send_charged_frame<T>(
        &mut self,
        input: &[u8],
        size: u64,
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let debit = self
            .outbound_used
            .checked_add(size)
            .ok_or(Error::Overflow)?;
        if debit > self.outbound_window {
            self.dirty = true;
            return Err(Error::WouldBlock);
        }
        let admitted = admit(input)?;
        self.outbound_used = debit;
        Ok(admitted)
    }

    /// Observe the current unused outbound grant before producing a payload.
    ///
    /// Final admission still checks the complete frame and the current grant.
    pub fn outbound_credit(&self) -> Result<u64, Error> {
        self.require_live()?;
        Ok(self.outbound_window.saturating_sub(self.outbound_used))
    }

    pub(crate) fn request_announcement(&mut self) {
        self.dirty = true;
    }

    /// Reserve one original inbound payload for the caller to deliver.
    ///
    /// The owner admits by actual retained capacity, since a lower new grant
    /// cannot revoke bytes already in flight. The caller retains the delivery
    /// receipt until the original consumer relinquishes its payload.
    ///
    /// # Errors
    /// Refuses overlapping payloads, unsupported controls and invalid sizes.
    pub fn admit_inbound(&mut self, input: &[u8]) -> Result<Delivery<'scope>, Error> {
        let size = self.payload_size(input)?;
        self.admit_size(size)
    }

    pub(crate) fn admit_classified(&mut self, length: usize) -> Result<Delivery<'scope>, Error> {
        let size = self.check_extent(length)?;
        self.admit_size(size)
    }

    fn admit_size(&mut self, size: u64) -> Result<Delivery<'scope>, Error> {
        if self.outstanding.is_some() {
            return Err(Error::WouldBlock);
        }
        self.inbound_window
            .checked_add(size)
            .ok_or(Error::Overflow)?;
        self.outstanding = Some(size);
        self.inbound_used = self.inbound_used.saturating_add(size);
        Ok(Delivery { scope: self.scope })
    }

    /// Release capacity only for the original delivered payload.
    ///
    /// # Errors
    /// A foreign or retired receipt is returned to its owner unchanged.
    pub fn release_inbound(
        &mut self,
        receipt: Delivery<'scope>,
    ) -> Result<(), Rejected<Delivery<'scope>>> {
        match self.release(&receipt) {
            Ok(()) => Ok(()),
            Err(reason) => Err(Rejected {
                value: receipt,
                reason,
            }),
        }
    }

    fn release(&mut self, receipt: &Delivery<'scope>) -> Result<(), Error> {
        self.require_live()?;
        if !ptr::eq(self.scope, receipt.scope) {
            return Err(Error::Stale);
        }
        let size = self.outstanding.ok_or(Error::Stale)?;
        self.inbound_window = self
            .inbound_window
            .checked_add(size)
            .ok_or(Error::Overflow)?;
        self.outstanding = None;
        self.dirty = true;
        Ok(())
    }

    /// Deadline for the initial, changed-window or periodic FLOW announcement.
    ///
    /// # Errors
    /// A closed link or unrepresentable deadline cannot schedule work.
    pub fn next_flow_at(&self) -> Result<MonoInstant, Error> {
        self.require_live()?;
        let Some(last) = &self.announcement else {
            return Ok(self.retry_at);
        };
        let delay = if self.dirty {
            FLOW_MIN_MICROS
        } else {
            FLOW_KEEPALIVE_MICROS
        };
        Ok(after(last.sent_at, delay)?.max(self.retry_at))
    }

    /// Offer one due FLOW control without consuming ordinary byte credit.
    ///
    /// The timestamp callback issues a finite, increasing GNUnet stamp from
    /// the original durable namespace. The admission callback submits the
    /// encoded control via the original carrier's reserved control capacity.
    /// Refusal may burn the issued stamp while preserving the unsent update.
    /// Every attempt observes the 100 ms minimum interval.
    ///
    /// # Errors
    /// Returns clock, timestamp, sequence and original admission failures.
    pub fn send_flow<T>(
        &mut self,
        now: MonoInstant,
        issue_stamp: impl FnOnce() -> Result<NonZeroU64, Error>,
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        let deadline = self.next_flow_at()?;
        if now.0 == u64::MAX
            || self
                .announcement
                .as_ref()
                .is_some_and(|last| now < last.sent_at)
        {
            return Err(Error::TimeUncertain);
        }
        if now < deadline {
            return Ok(None);
        }
        let next_sequence = self.local_sequence.checked_add(1).ok_or(Error::Overflow)?;
        after(now, FLOW_KEEPALIVE_MICROS)?;
        self.retry_at = after(now, FLOW_MIN_MICROS)?;
        let sender_time = issue_stamp()?;
        if sender_time.get() == u64::MAX
            || self
                .announcement
                .as_ref()
                .is_some_and(|last| sender_time <= last.sender_time)
        {
            return Err(Error::TimeUncertain);
        }
        let flow = Flow {
            sequence: self.local_sequence,
            inbound_window: self.inbound_window,
            outbound_sent: self.outbound_used,
            outbound_window: self.outbound_window,
            sender_time: sender_time.get(),
            rtt: u64::MAX,
            sync_ready: false,
        };
        let admitted = admit(&flow.encode())?;
        self.announcement = Some(Announcement {
            sent_at: now,
            sender_time,
            window: self.inbound_window,
        });
        self.local_sequence = next_sequence;
        self.dirty = false;
        Ok(Some(admitted))
    }

    /// Current non-authoritative counters and last submitted FLOW.
    #[must_use]
    pub fn observation(&self) -> Observation {
        let loss = self.remote.as_ref().map_or(0, |remote| {
            (i128::from(remote.sent_bytes) - i128::from(self.inbound_used))
                .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
        });
        Observation {
            receive_capacity: DEFAULT_WINDOW,
            inbound_held: self.outstanding.unwrap_or(0),
            inbound_window: self.announcement.as_ref().map_or(0, |last| last.window),
            inbound_used: self.inbound_used,
            inbound_loss: loss,
            outbound_window: self.outbound_window,
            outbound_used: self.outbound_used,
            peer_rtt: self.remote.as_ref().map_or(u64::MAX, |remote| remote.rtt),
            last_announcement: self.announcement.as_ref().map(|last| last.sent_at),
        }
    }

    /// Retire the original carrier and fence every outstanding receipt.
    pub fn cancel(&mut self) {
        self.closed = true;
    }

    fn require_live(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    fn payload_size(&self, input: &[u8]) -> Result<u64, Error> {
        self.require_live()?;
        let frame = Frame::decode(input)?;
        if matches!(
            frame.header().message_type(),
            mt::TRANSPORT_BACKCHANNEL_ENCAPSULATION
                | mt::TRANSPORT_FRAGMENT
                | mt::TRANSPORT_RELIABILITY_BOX
                | mt::TRANSPORT_RELIABILITY_ACK
                | mt::TRANSPORT_DV_LEARN
                | mt::TRANSPORT_DV_BOX
                | mt::TRANSPORT_FLOW_CONTROL
                | mt::TRANSPORT_ADDRESS_VALIDATION_CHALLENGE
                | mt::TRANSPORT_ADDRESS_VALIDATION_RESPONSE
        ) {
            return Err(Error::Unsupported);
        }
        self.check_extent(frame.encoded_len())
    }

    fn check_extent(&self, length: usize) -> Result<u64, Error> {
        self.require_live()?;
        let size = length as u64;
        if size > self.max_payload {
            return Err(Error::TooLarge);
        }
        Ok(size)
    }
}

fn after(now: MonoInstant, delay: u64) -> Result<MonoInstant, Error> {
    now.0
        .checked_add(delay)
        .filter(|value| *value != u64::MAX)
        .map(MonoInstant)
        .ok_or(Error::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD: [u8; 4] = [0, 4, 0, 83];

    fn update(sequence: u32, time: u64, grant: u64, sent: u64) -> [u8; 60] {
        Flow {
            sequence,
            inbound_window: grant,
            outbound_sent: sent,
            outbound_window: DEFAULT_WINDOW,
            sender_time: time,
            rtt: u64::MAX,
            sync_ready: false,
        }
        .encode()
    }

    fn stamp(value: u64) -> Result<NonZeroU64, Error> {
        NonZeroU64::new(value).ok_or(Error::InvalidInput)
    }

    #[test]
    fn send_debit_requires_admission_and_survives_stale_flow() -> Result<(), Error> {
        let mut scope = Scope::new();
        let capacity = NonZeroU16::new(64).ok_or(Error::InvalidInput)?;
        let mut link = DirectFlow::new(&mut scope, capacity)?;
        link.receive_flow(&update(10, 10, 6, 0))?;
        if link.send_payload(&PAYLOAD, |_| Err::<(), _>(Error::Capacity)) != Err(Error::Capacity)
            || link.outbound_credit()? != 6
        {
            return Err(Error::InvalidInput);
        }
        link.send_payload(&PAYLOAD, |_| Ok(()))?;
        if link.receive_flow(&update(9, 9, 8, 0)) != Err(Error::Replay)
            || link.send_payload(&PAYLOAD, |_| Err::<(), _>(Error::Io)) != Err(Error::WouldBlock)
            || link.outbound_credit()? != 2
        {
            return Err(Error::InvalidInput);
        }
        link.receive_flow(&update(9, 11, 8, 0))?;
        if link.outbound_credit()? != 8 {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    #[test]
    fn release_uses_original_scope_and_real_retained_charge() -> Result<(), Error> {
        let mut first_scope = Scope::new();
        let mut second_scope = Scope::new();
        let capacity = NonZeroU16::new(64).ok_or(Error::InvalidInput)?;
        let mut first = DirectFlow::new(&mut first_scope, capacity)?;
        let mut second = DirectFlow::new(&mut second_scope, capacity)?;
        let delivery = first.admit_inbound(&PAYLOAD)?;
        let foreign = second
            .release_inbound(delivery)
            .err()
            .ok_or(Error::InvalidInput)?;
        let excessive = update(0, 1, 0, u64::MAX - DEFAULT_WINDOW - 3);
        if foreign.reason != Error::Stale || first.receive_flow(&excessive) != Err(Error::Overflow)
        {
            return Err(Error::InvalidInput);
        }

        first.receive_flow(&update(0, 2, 0, 10))?;
        if first.admit_inbound(&PAYLOAD).err() != Some(Error::WouldBlock) {
            return Err(Error::InvalidInput);
        }
        first
            .release_inbound(foreign.value)
            .map_err(|rejected| rejected.reason)?;
        let flow = first
            .send_flow(MonoInstant(1), || stamp(1), Flow::decode)?
            .ok_or(Error::NotReady)?;
        let observed = first.observation();
        if flow.inbound_window != DEFAULT_WINDOW + 14
            || flow.outbound_window != 0
            || observed.inbound_window != flow.inbound_window
            || observed.inbound_held != 0
            || observed.inbound_used != 4
            || observed.inbound_loss != 6
            || observed.last_announcement != Some(MonoInstant(1))
        {
            return Err(Error::InvalidInput);
        }
        {
            let _abandoned = first.admit_inbound(&PAYLOAD)?;
        }
        if first.admit_inbound(&PAYLOAD).err() != Some(Error::WouldBlock) {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    #[test]
    fn rejected_flow_throttles_without_consuming_its_sequence() -> Result<(), Error> {
        let mut scope = Scope::new();
        let capacity = NonZeroU16::new(64).ok_or(Error::InvalidInput)?;
        let mut link = DirectFlow::new(&mut scope, capacity)?;
        let outcome = link.send_flow(
            MonoInstant(1),
            || stamp(1),
            |_| Err::<(), _>(Error::Capacity),
        );
        let due = MonoInstant(1 + FLOW_MIN_MICROS);
        if outcome != Err(Error::Capacity)
            || link.next_flow_at()? != due
            || link
                .send_flow(MonoInstant(2), || Err(Error::Entropy), Flow::decode)?
                .is_some()
        {
            return Err(Error::InvalidInput);
        }
        let flow = link
            .send_flow(due, || stamp(2), Flow::decode)?
            .ok_or(Error::NotReady)?;
        if flow.sequence != 0
            || flow.sender_time != 2
            || flow.rtt != u64::MAX
            || flow.sync_ready
            || link.next_flow_at()? != MonoInstant(due.0 + FLOW_KEEPALIVE_MICROS)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
