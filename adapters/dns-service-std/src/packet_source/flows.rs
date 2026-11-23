//! Bounded application-flow ownership; no packet injection or endpoint synthesis.
use super::{Error, PacketExposure, PendingOutput, core, input};
use gnunet_native::dns_proxy::{ReadDatagram, ReadLimits, UdpFlow};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use std::{collections::VecDeque, io, pin::Pin, time::Duration};
use tokio::time::{Instant, Sleep};
mod multicast;
mod poll;
mod state;
use state::{FlowState, Phase};

/// Bounds for original application flows and each asynchronous read batch.
#[derive(Clone, Copy, Debug)]
pub struct FlowLimits {
    /// Maximum live flows, including closing flows with outstanding callbacks.
    pub flows: usize,
    /// Original native read bounds, independent of the engine payload budget.
    pub read: ReadLimits,
    /// Finite time allowed for opening an accepted application flow.
    pub open_timeout: Duration,
    /// Hard lifetime of an explicitly enabled original-destination DNS exchange.
    pub multicast_timeout: Option<Duration>,
}
impl Default for FlowLimits {
    fn default() -> Self {
        Self {
            flows: 32,
            read: ReadLimits {
                datagrams: 16,
                datagram_bytes: core::MAX_DNS_BYTES,
                batch_bytes: 128 * 1024,
            },
            open_timeout: Duration::from_secs(5),
            multicast_timeout: None,
        }
    }
}
/// Refused admission preserves the same native flow for explicit retirement.
#[derive(Debug)]
pub struct RejectedFlow {
    /// Pre-admission error; no flow was added to this source.
    pub error: io::Error,
    /// Original SDK owner; it has not been replaced or rebound.
    pub flow: UdpFlow,
}
/// Closed flow directions and retired callback loans, without a provider ACK.
#[derive(Debug, Default)]
pub struct FlowRetirement {
    /// Number of original flows whose callback loans actually retired.
    pub retired: u64,
    /// Datagrams refused by the bounded native read adapter.
    pub refused: u64,
    /// First SDK operation failure, independent of callback retirement.
    pub first_error: Option<io::Error>,
    /// First failed callback retirement receipt; subsequent faults are counted.
    pub first_retirement: Option<gnunet_native::dns_proxy::Retirement>,
    /// Number of failed callback retirement receipts.
    pub retirement_failures: u64,
    /// Multicast replies actually accepted by the original application's SDK write.
    pub multicast_writes_accepted: u64,
    /// Accepted multicast writes whose deadline or flow had already closed.
    pub multicast_writes_late: u64,
}
impl FlowRetirement {
    /// Whether any observed operation or callback retirement failed.
    pub fn has_failure(&self) -> bool {
        self.first_error.is_some() || self.retirement_failures != 0
    }
}
struct Entry<'id> {
    flow: UdpFlow,
    state: FlowState<'id>,
    reading: bool,
    buffered: VecDeque<ReadDatagram>,
    multicast: Option<multicast::Exchange>,
}

impl Entry<'_> {
    fn take_read(&mut self) -> Option<ReadDatagram> {
        if self.multicast.is_none() {
            return self.buffered.pop_front();
        }
        // A group exchange can keep its original callbacks for its entire
        // deadline. Unicast datagrams in the same bounded batch stay eligible,
        // in their original order, while later group requests wait.
        let ready = self
            .buffered
            .iter()
            .position(|datagram| matches!(datagram, ReadDatagram::Unicast(_)))?;
        self.buffered.remove(ready)
    }

    fn can_write(&self) -> bool {
        self.state.can_write()
            && self.flow.writable()
            && !self
                .multicast
                .as_ref()
                .is_some_and(multicast::Exchange::reserves_write)
    }

    fn stop(&mut self, reason: Fault, notified: bool) {
        self.state.stop(reason, notified);
        self.close_io();
    }

    fn close_io(&mut self) {
        if let Some(exchange) = &mut self.multicast {
            exchange.stop(&mut self.flow);
        }
        self.flow.request_close();
        self.buffered = VecDeque::new();
    }
}
pub(super) struct Flows<'id> {
    entries: Vec<Option<Entry<'id>>>,
    limits: FlowLimits,
    closing: bool,
    report: Option<FlowRetirement>,
    cursor: usize,
    timer: Pin<Box<Sleep>>,
}
impl<'id> Flows<'id> {
    pub fn new(limits: FlowLimits) -> Result<Self, Fault> {
        if limits.flows == 0
            || !(1..=1024).contains(&limits.read.datagrams)
            || !(12..=core::MAX_DNS_BYTES).contains(&limits.read.datagram_bytes)
            || limits.read.batch_bytes < limits.read.datagram_bytes
            || limits.open_timeout.is_zero()
            || Instant::now().checked_add(limits.open_timeout).is_none()
            || limits.multicast_timeout.is_some_and(|lifetime| {
                lifetime.is_zero() || Instant::now().checked_add(lifetime).is_none()
            })
        {
            return Err(Fault::InvalidInput);
        }
        limits
            .flows
            .checked_mul(limits.read.batch_bytes)
            .ok_or(Fault::Overflow)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.flows)
            .map_err(|_| Fault::Capacity)?;
        entries.resize_with(limits.flows, || None);
        Ok(Self {
            entries,
            limits,
            closing: false,
            report: Some(FlowRetirement::default()),
            cursor: 0,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
        })
    }
    #[expect(
        clippy::result_large_err,
        reason = "Pre-admission refusal preserves the original SDK owner without a fallible error allocation"
    )]
    pub fn insert(&mut self, mut flow: UdpFlow) -> Result<(), RejectedFlow> {
        let prepared = (|| {
            if self.closing {
                return Err(io::ErrorKind::NotConnected.into());
            }
            if self
                .entries
                .iter()
                .flatten()
                .any(|e| e.flow.id() == flow.id())
            {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            let slot = self
                .entries
                .iter()
                .position(Option::is_none)
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
            let until = Instant::now()
                .checked_add(self.limits.open_timeout)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            flow.begin_open()?;
            Ok((slot, until))
        })();
        match prepared {
            Ok((slot, until)) => {
                self.entries[slot] = Some(Entry {
                    flow,
                    state: FlowState::opening(until),
                    reading: false,
                    buffered: VecDeque::new(),
                    multicast: None,
                });
                Ok(())
            }
            Err(error) => Err(RejectedFlow { error, flow }),
        }
    }
    pub fn initialized(&self) -> bool {
        !self.closing
    }
    pub fn writable(&self) -> bool {
        !self.closing && self.entries.iter().flatten().any(Entry::can_write)
    }
    pub fn write_available(&self, endpoint: &gnunet_native::dns_proxy::ReplyEndpoint) -> bool {
        !self.closing
            && self
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.flow.id() == endpoint.flow_id() && entry.can_write())
    }
    pub fn accepts(&self, endpoint: &gnunet_native::dns_proxy::ReplyEndpoint) -> bool {
        self.entries.iter().flatten().any(|entry| {
            entry.flow.id() == endpoint.flow_id() && matches!(entry.state.phase(), Phase::Open)
        })
    }
    pub fn pending_capacity(&self) -> usize {
        self.entries.len()
    }
    pub fn pending_at(&self, index: usize) -> Option<PendingOutput<'id>> {
        let output = self.entries.get(index)?.as_ref()?.state.pending()?;
        Some(PendingOutput {
            effect: output.effect,
            exposure: PacketExposure::FlowWritePending,
            total: output.bytes,
        })
    }
    #[expect(
        clippy::result_large_err,
        reason = "Pre-submission refusal preserves both original payload and noncloneable native reply permit without allocation"
    )]
    pub fn queue(
        &mut self,
        effect: core::Effect<'id>,
        frame: OwnedFrame,
        until: Instant,
        permit: input::ReplyPermit<'id>,
    ) -> Result<(), (Error, OwnedFrame, input::ReplyPermit<'id>)> {
        let refusal = if !self.writable() {
            Some(Fault::WouldBlock)
        } else if Instant::now() >= until {
            Some(Fault::Deadline)
        } else {
            None
        };
        if let Some(error) = refusal {
            return Err((error.into(), frame, permit));
        }
        let Some(slot) = self.entries.iter().position(|entry| {
            entry.as_ref().is_some_and(|e| {
                Some(e.flow.id()) == permit.flow_id() && matches!(e.state.phase(), Phase::Open)
            })
        }) else {
            return Err((Fault::StaleGeneration.into(), frame, permit));
        };
        let Some(entry) = self.entries[slot].as_mut() else {
            return Err((Fault::StaleGeneration.into(), frame, permit));
        };
        if !entry.can_write() {
            return Err((Fault::WouldBlock.into(), frame, permit));
        }
        let (identity, route) = permit.into_parts();
        let input::ReplyOwner::Flow(endpoint) = route else {
            return Err((
                Fault::InvalidInput.into(),
                frame,
                identity.with_owner(route),
            ));
        };
        let bytes = frame.len();
        let reservation = match entry.state.begin(effect, bytes, Instant::now(), until) {
            Ok(reservation) => reservation,
            Err(error) => {
                return Err((
                    error.into(),
                    frame,
                    identity.with_owner(input::ReplyOwner::Flow(endpoint)),
                ));
            }
        };
        match entry.flow.begin_write(frame.into_bytes(), endpoint) {
            Ok(()) => {
                reservation.submitted();
                Ok(())
            }
            Err(rejected) => {
                let (error, bytes, endpoint) = rejected.into_parts();
                if error.kind() != io::ErrorKind::WouldBlock {
                    entry.stop(Fault::Closed, false);
                }
                Err((
                    error.into(),
                    OwnedFrame::new(bytes),
                    identity.with_owner(input::ReplyOwner::Flow(endpoint)),
                ))
            }
        }
    }
    pub fn cancel_output(&mut self, request: core::Request<'id>) -> Result<(), Error> {
        let entry = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| {
                entry
                    .state
                    .pending()
                    .is_some_and(|output| output.effect.request() == request)
            })
            .ok_or(Fault::StaleGeneration)?;
        if entry.state.expire(Instant::now()) {
            entry.close_io();
        } else {
            entry.stop(Fault::Cancelled, false);
        }
        Ok(())
    }
    fn failure(&mut self, error: io::Error) {
        if let Some(report) = &mut self.report
            && report.first_error.is_none()
        {
            report.first_error = Some(error);
        }
    }
    pub fn close(&mut self) {
        self.closing = true;
        for entry in self.entries.iter_mut().flatten() {
            entry.stop(Fault::Closed, true);
        }
    }
}
