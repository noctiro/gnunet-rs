//! Bounded actual forwarding owner. All IO/clock/entropy is an explicit port.
use crate::{
    AfProfile, Family,
    nat::{Entropy, Pool},
    policy::{Endpoint, Policy, Protocol, Tuple},
};
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use gnunet_types::{Error, MonoInstant};
use gnunet_vpn::packet::{self, Packet};
use gnunet_wire::official::vpn::PeerMessage;
mod types;
use types::Stamp;
pub use types::{
    Closed, Config, Dns, Effect, Flow, Info, Input, Limits, Output, Service, Source, Target,
    TcpState, Tun, Write,
};
mod dns;
mod forward;
mod returned;
struct Receipt {
    id: Input,
    ready: bool,
    issued: bool,
    expires: u64,
}
struct DnsJob {
    id: Dns,
    query: Vec<u8>,
    original: [u8; 2],
    wire: [u8; 2],
    issued: bool,
    admitted: bool,
    written: bool,
    cancelling: bool,
    cancel_issued: bool,
}
struct Processing {
    flow: Flow,
    source: Source,
    input: Input,
    expires: u64,
}
struct Record {
    flow: Flow,
    source: Source,
    peer: [u8; 32],
    target: Target,
    tuple: Option<Tuple>,
    last: u64,
    idle: u64,
    closing: bool,
    close_issued: bool,
    peer_closed: bool,
    receipt: Option<Receipt>,
    dns: Option<DnsJob>,
    tcp: TcpState,
    syn_end: Option<u32>,
    failure: Option<Error>,
    reuse: Option<u64>,
    reported: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Side {
    Tun,
    Peer,
}
struct Pending {
    write: Write,
    flow: Flow,
    source: u64,
    bytes: Vec<u8>,
    leased: bool,
    input: Option<Input>,
    expires: u64,
}
/// One explicit no_std/alloc EXIT forwarding engine. Actual native adapters own
/// all CADET/TUN/DNS sockets and report their original physical completions.
pub struct Engine<'a> {
    config: Config<'a>,
    limits: Limits,
    stamp: Rc<Stamp>,
    next: u64,
    source: Option<Source>,
    tun: Option<Tun>,
    flows: Vec<Option<Record>>,
    processing: Vec<Processing>,
    tun_queue: VecDeque<Pending>,
    peer_queue: VecDeque<Pending>,
    queued_bytes: usize,
    last: Option<u64>,
    stopping: bool,
    source_close_issued: bool,
    tun_close_issued: bool,
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Capacity)?;
    v.extend_from_slice(bytes);
    Ok(v)
}
fn zero(n: usize) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize(n, 0);
    Ok(v)
}
impl<'a> Engine<'a> {
    /// Validate explicit configured sources and reserve bounded metadata only.
    pub fn new(config: Config<'a>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        config.af.validate()?;
        config.policy.validate()?;
        if let Some(p) = config.ipv4 {
            p.validate()?;
            if p.family() != Family::V4 {
                return Err(Error::InvalidInput);
            }
        }
        if let Some(p) = config.ipv6 {
            p.validate()?;
            if p.family() != Family::V6 {
                return Err(Error::InvalidInput);
            }
        }
        for (i, s) in config.services.iter().enumerate() {
            if !matches!(s.protocol, Protocol::Tcp | Protocol::Udp)
                || config.services[..i]
                    .iter()
                    .any(|p| p.port == s.port && p.protocol == s.protocol)
            {
                return Err(Error::Conflict);
            }
        }
        let mut flows = Vec::new();
        flows
            .try_reserve_exact(limits.flows)
            .map_err(|_| Error::Capacity)?;
        flows.resize_with(limits.flows, || None);
        Ok(Self {
            config,
            limits,
            stamp: Rc::new(Stamp { _marker: 0 }),
            next: 0,
            source: None,
            tun: None,
            flows,
            processing: Vec::new(),
            tun_queue: VecDeque::new(),
            peer_queue: VecDeque::new(),
            queued_bytes: 0,
            last: None,
            stopping: false,
            source_close_issued: false,
            tun_close_issued: false,
        })
    }
    fn serial(&mut self) -> Result<u64, Error> {
        let n = self.next.checked_add(1).ok_or(Error::Overflow)?;
        self.next = n;
        Ok(n)
    }
    fn time(&mut self, now: MonoInstant) -> Result<u64, Error> {
        if self.last.is_some_and(|old| now.0 < old) {
            return Err(Error::TimeUncertain);
        }
        self.last = Some(now.0);
        Ok(now.0)
    }
    fn index(&self, flow: &Flow) -> Result<usize, Error> {
        if !Rc::ptr_eq(&self.stamp, &flow.owner) {
            return Err(Error::Stale);
        }
        self.flows
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.flow == *flow))
            .ok_or(Error::Stale)
    }
    fn valid_source(&self, source: &Source) -> Result<(), Error> {
        if self.source.as_ref() == Some(source) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    /// Register one actual CADET attachment after native success. No IO is done.
    pub fn attached(&mut self) -> Result<Source, Error> {
        if self.stopping {
            return Err(Error::Closed);
        }
        self.source_close_issued = false;
        if self.source.is_some() {
            return Err(Error::Conflict);
        }
        let source = Source {
            owner: self.stamp.clone(),
            serial: self.serial()?,
        };
        self.source = Some(source.clone());
        Ok(source)
    }
    /// Register an actually opened/verified TUN device, never an arbitrary fd.
    pub fn tun_attached(&mut self) -> Result<Tun, Error> {
        if self.stopping {
            return Err(Error::Closed);
        }
        self.tun_close_issued = false;
        if self.tun.is_some() {
            return Err(Error::Conflict);
        }
        let tun = Tun {
            owner: self.stamp.clone(),
            serial: self.serial()?,
        };
        self.tun = Some(tun.clone());
        Ok(tun)
    }
    /// Bind metadata to one actual accepted original CADET channel. A full table
    /// requests oldest live closure and returns WouldBlock; no slot is reused
    /// until its real IO debts and configured NAT quarantine are finished.
    pub fn accept(
        &mut self,
        source: &Source,
        peer: [u8; 32],
        target: Target,
        now: MonoInstant,
    ) -> Result<Flow, Error> {
        self.valid_source(source)?;
        let now = self.time(now)?;
        match target {
            Target::Internet(Family::V4) if !self.config.policy.ipv4 => {
                return Err(Error::Unavailable);
            }
            Target::Internet(Family::V6) if !self.config.policy.ipv6 => {
                return Err(Error::Unavailable);
            }
            Target::Service(port) if !self.config.services.iter().any(|s| s.port == port) => {
                return Err(Error::NotFound);
            }
            Target::Dns if !self.config.dns => return Err(Error::Unavailable),
            _ => {}
        }
        let Some(i) = self.flows.iter().position(Option::is_none) else {
            if let Some(i) = self
                .flows
                .iter()
                .enumerate()
                .filter_map(|(i, r)| r.as_ref().filter(|r| !r.closing).map(|r| (i, r.last)))
                .min_by_key(|(_, t)| *t)
                .map(|(i, _)| i)
            {
                self.close_index(i, Some(Error::Capacity));
            }
            return Err(Error::WouldBlock);
        };
        let idle = now.checked_add(self.limits.idle).ok_or(Error::Overflow)?;
        let flow = Flow {
            owner: self.stamp.clone(),
            serial: self.serial()?,
        };
        self.flows[i] = Some(Record {
            flow: flow.clone(),
            source: source.clone(),
            peer,
            target,
            tuple: None,
            last: now,
            idle,
            closing: false,
            close_issued: false,
            peer_closed: false,
            receipt: None,
            dns: None,
            tcp: TcpState::default(),
            syn_end: None,
            failure: None,
            reuse: None,
            reported: false,
        });
        Ok(flow)
    }
    /// Exact original observed flow metadata; no native authority is minted.
    pub fn info(&self, flow: &Flow) -> Result<Info, Error> {
        let r = self.flows[self.index(flow)?].as_ref().ok_or(Error::Stale)?;
        Ok(Info {
            source: r.source.clone(),
            peer: r.peer,
            target: r.target,
            tuple: r.tuple,
            closing: r.closing,
            peer_closed: r.peer_closed,
            tcp: r.tcp,
        })
    }
    fn capacity(&self, n: usize) -> Result<(), Error> {
        if n > self.limits.output_bytes {
            return Err(Error::Capacity);
        }
        if self
            .tun_queue
            .len()
            .checked_add(self.peer_queue.len())
            .is_none_or(|n| n >= self.limits.output_frames)
            || self
                .queued_bytes
                .checked_add(n)
                .is_none_or(|n| n > self.limits.output_bytes)
        {
            Err(Error::WouldBlock)
        } else {
            Ok(())
        }
    }
    fn queue(
        &mut self,
        side: Side,
        flow: &Flow,
        bytes: Vec<u8>,
        input: Option<Input>,
    ) -> Result<(), Error> {
        self.capacity(bytes.len())?;
        let source = match side {
            Side::Tun => self.tun.as_ref().ok_or(Error::NotReady)?.serial,
            Side::Peer => {
                self.flows[self.index(flow)?]
                    .as_ref()
                    .ok_or(Error::Stale)?
                    .source
                    .serial
            }
        };
        let expires = self
            .last
            .ok_or(Error::NotReady)?
            .checked_add(self.limits.input_lifetime)
            .ok_or(Error::Overflow)?;
        let write = Write {
            owner: self.stamp.clone(),
            serial: self.serial()?,
        };
        let q = match side {
            Side::Tun => &mut self.tun_queue,
            Side::Peer => &mut self.peer_queue,
        };
        q.try_reserve(1).map_err(|_| Error::Capacity)?;
        self.queued_bytes += bytes.len();
        q.push_back(Pending {
            write,
            flow: flow.clone(),
            source,
            bytes,
            leased: false,
            input,
            expires,
        });
        Ok(())
    }
    fn queue_peer(&mut self, flow: &Flow, message: PeerMessage<'_>) -> Result<(), Error> {
        let n = message.encoded_len()?;
        if n > self.limits.peer_bytes {
            return Err(Error::TooLarge);
        }
        let mut b = zero(n)?;
        message.encode_with_profile(&mut b, self.config.af)?;
        self.queue(Side::Peer, flow, b, None)
    }
    fn output(queue: &mut VecDeque<Pending>) -> Option<Output<'_>> {
        let p = queue.front_mut()?;
        p.leased = true;
        Some(Output {
            write: p.write.clone(),
            flow: p.flow.clone(),
            bytes: &p.bytes,
            expires: MonoInstant(p.expires),
        })
    }
    /// Original immutable whole IP packet; never retry a suffix as a new packet.
    pub fn tun_output(&mut self) -> Option<Output<'_>> {
        Self::output(&mut self.tun_queue)
    }
    /// Original immutable official CADET message, never replayed on another MQ.
    pub fn peer_output(&mut self) -> Option<Output<'_>> {
        Self::output(&mut self.peer_queue)
    }
    fn written(&mut self, side: Side, write: &Write) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.stamp, &write.owner) {
            return Err(Error::Stale);
        }
        let q = match side {
            Side::Tun => &mut self.tun_queue,
            Side::Peer => &mut self.peer_queue,
        };
        let p = q.front().ok_or(Error::Stale)?;
        if p.write != *write || !p.leased {
            return Err(Error::Stale);
        }
        let p = q.pop_front().ok_or(Error::Stale)?;
        self.queued_bytes -= p.bytes.len();
        if let Some(input) = p.input {
            let index = self.index(&p.flow)?;
            let r = self.flows[index].as_mut().ok_or(Error::Stale)?;
            if let Some(receipt) = &mut r.receipt
                && receipt.id == input
                && !r.closing
            {
                receipt.ready = true;
            }
        }
        Ok(())
    }
    /// Actual original complete packet write, not remote TCP/UDP acceptance.
    pub fn tun_written(&mut self, tun: &Tun, write: &Write) -> Result<(), Error> {
        if self.tun.as_ref() != Some(tun)
            || self
                .tun_queue
                .front()
                .is_none_or(|p| p.source != tun.serial)
        {
            return Err(Error::Stale);
        }
        self.written(Side::Tun, write)
    }
    /// Actual original complete native message write, not peer processing.
    pub fn peer_written(&mut self, source: &Source, write: &Write) -> Result<(), Error> {
        self.valid_source(source)?;
        if self
            .peer_queue
            .front()
            .is_none_or(|p| p.source != source.serial)
        {
            return Err(Error::Stale);
        }
        self.written(Side::Peer, write)
    }
    fn unsent(&mut self, side: Side, write: &Write, error: Error) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.stamp, &write.owner) {
            return Err(Error::Stale);
        }
        let queue = match side {
            Side::Tun => &mut self.tun_queue,
            Side::Peer => &mut self.peer_queue,
        };
        if queue.front().is_none_or(|p| p.write != *write || !p.leased) {
            return Err(Error::Stale);
        }
        let p = queue.pop_front().ok_or(Error::Stale)?;
        self.queued_bytes -= p.bytes.len();
        let i = self.index(&p.flow)?;
        self.close_index(i, Some(error));
        Ok(())
    }
    /// Actual original native port proved this whole packet transferred no byte
    /// (Unsent). Logical expiry alone is insufficient proof. Positive short write
    /// requires actual TUN close and tun_lost instead of this callback.
    pub fn tun_unsent(&mut self, tun: &Tun, write: &Write, error: Error) -> Result<(), Error> {
        if self.tun.as_ref() != Some(tun)
            || self
                .tun_queue
                .front()
                .is_none_or(|p| p.source != tun.serial)
        {
            return Err(Error::Stale);
        }
        self.unsent(Side::Tun, write, error)
    }
    /// Actual original MQ port proved zero exposure and retired that immutable
    /// frame. An admitted partial suffix must drain or the MQ must really close.
    pub fn peer_unsent(
        &mut self,
        source: &Source,
        write: &Write,
        error: Error,
    ) -> Result<(), Error> {
        self.valid_source(source)?;
        if self
            .peer_queue
            .front()
            .is_none_or(|p| p.source != source.serial)
        {
            return Err(Error::Stale);
        }
        self.unsent(Side::Peer, write, error)
    }
    fn close_index(&mut self, index: usize, failure: Option<Error>) {
        let Some(r) = self.flows[index].as_mut() else {
            return;
        };
        r.closing = true;
        if r.failure.is_none() {
            r.failure = failure
        }
        if r.dns.as_ref().is_some_and(|dns| !dns.issued) {
            r.dns = None;
        } else if let Some(dns) = &mut r.dns {
            dns.cancelling = true;
        }
        if r.receipt.as_ref().is_some_and(|receipt| !receipt.issued) {
            r.receipt = None;
        }
        let flow = r.flow.clone();
        for q in [&mut self.tun_queue, &mut self.peer_queue] {
            q.retain(|p| {
                let keep = p.flow != flow || p.leased;
                if !keep {
                    self.queued_bytes -= p.bytes.len();
                }
                keep
            });
        }
    }
    /// Request actual original channel closure; all admitted leases retain debt.
    pub fn close(&mut self, flow: &Flow) -> Result<(), Error> {
        let i = self.index(flow)?;
        self.close_index(i, None);
        Ok(())
    }
    /// Observe actual peer-channel destruction while the native owner still
    /// holds earlier DATA. Only that original input may finish forwarding;
    /// `closed` follows its real processing completion or local cancellation.
    ///
    /// `unadmitted` is the exact peer output borrowed but never admitted to the
    /// native MQ. Other leased output retains its actual write/loss debt. New
    /// replies have no consumer; this observation grants no processing or ACK.
    pub fn peer_ended(&mut self, flow: &Flow, unadmitted: Option<&Write>) -> Result<(), Error> {
        let index = self.index(flow)?;
        if let Some(write) = unadmitted
            && self
                .peer_queue
                .front()
                .is_none_or(|p| p.flow != *flow || p.write != *write || !p.leased)
        {
            return Err(Error::Stale);
        }
        self.flows[index].as_mut().ok_or(Error::Stale)?.peer_closed = true;
        self.peer_queue.retain(|p| {
            let keep = p.flow != *flow || (p.leased && unadmitted != Some(&p.write));
            if !keep {
                self.queued_bytes -= p.bytes.len();
            }
            keep
        });
        Ok(())
    }
    /// Actual original channel close callback. Original leased MQ/TUN packets
    /// remain until their own real writes or source-loss callbacks settle them.
    pub fn closed(&mut self, flow: &Flow) -> Result<(), Error> {
        let i = self.index(flow)?;
        self.close_index(i, None);
        self.flows[i].as_mut().ok_or(Error::Stale)?.peer_closed = true;
        Ok(())
    }
    /// Actual MQ loss after physical detach. Desired new attachments get new
    /// generations; old payloads/flows cannot replay or acquire that new source.
    pub fn source_lost(&mut self, source: &Source) -> Result<(), Error> {
        self.valid_source(source)?;
        self.source = None;
        for i in 0..self.flows.len() {
            if self.flows[i].as_ref().is_some_and(|r| r.source == *source) {
                self.close_index(i, Some(Error::Io));
                let r = self.flows[i].as_mut().ok_or(Error::Stale)?;
                r.peer_closed = true;
                r.receipt = None;
            }
        }
        self.peer_queue.retain(|p| {
            let keep = p.source != source.serial;
            if !keep {
                self.queued_bytes -= p.bytes.len()
            }
            keep
        });
        self.processing.retain(|p| p.source != *source);
        Ok(())
    }
    /// Actual device close/loss. Every old whole packet is retired, including an
    /// unknown positive short write. No suffix or packet is moved to a new TUN.
    pub fn tun_lost(&mut self, tun: &Tun, uncertain: Option<&Write>) -> Result<(), Error> {
        if self.tun.as_ref() != Some(tun) {
            return Err(Error::Stale);
        }
        if let Some(write) = uncertain
            && !self.tun_queue.iter().any(|p| p.write == *write && p.leased)
        {
            return Err(Error::Stale);
        }
        self.tun = None;
        for p in &self.tun_queue {
            if let Some(r) = self.flows.iter_mut().flatten().find(|r| r.flow == p.flow) {
                r.closing = true;
                if uncertain.is_some_and(|w| *w == p.write) {
                    r.failure = Some(Error::OutcomeUnknown)
                } else if r.failure.is_none() {
                    r.failure = Some(Error::Io)
                }
            }
        }
        self.tun_queue.clear();
        self.queued_bytes = self.peer_queue.iter().map(|p| p.bytes.len()).sum();
        for i in 0..self.flows.len() {
            if self.flows[i].as_ref().is_some_and(|r| r.tuple.is_some()) {
                self.close_index(i, Some(Error::Io));
            }
        }
        Ok(())
    }
    /// Global explicit inner-receipt capacity. A native owner must reserve its
    /// channels*maximum-inner-frames product before accepting any packed DATA.
    #[must_use]
    pub const fn processing_capacity(&self) -> usize {
        self.limits.processing_receipts
    }
    /// Configured finite original processing lifetime in microseconds. A native
    /// owner can capture an earlier outer-packet retirement bound at DATA receipt
    /// without minting a new target after physical peer destruction.
    #[must_use]
    pub const fn input_lifetime(&self) -> u64 {
        self.limits.input_lifetime
    }
    /// Move this exact ready+issued inner receipt into the original outer ACK
    /// debt table. This is not an ACK or processing retirement. Admission failure
    /// preserves the original current receipt/source so the caller can retry.
    pub fn processing_batched(&mut self, input: &Input) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.stamp, &input.owner) {
            return Err(Error::Stale);
        }
        let index = self
            .flows
            .iter()
            .position(|r| {
                r.as_ref()
                    .is_some_and(|r| r.receipt.as_ref().is_some_and(|p| p.id == *input))
            })
            .ok_or(Error::Stale)?;
        let r = self.flows[index].as_ref().ok_or(Error::Stale)?;
        if r.closing || r.receipt.as_ref().is_none_or(|p| !p.ready || !p.issued) {
            return Err(Error::NotReady);
        }
        if self.processing.len() >= self.limits.processing_receipts {
            return Err(Error::WouldBlock);
        }
        self.processing
            .try_reserve(1)
            .map_err(|_| Error::Capacity)?;
        let r = self.flows[index].as_mut().ok_or(Error::Stale)?;
        let receipt = r.receipt.take().ok_or(Error::Stale)?;
        self.processing.push(Processing {
            flow: r.flow.clone(),
            source: r.source.clone(),
            input: receipt.id,
            expires: receipt.expires,
        });
        Ok(())
    }
    /// A real native receive_done write (or host aggregate for its exact outer
    /// Delivery) acknowledged this original completed frame-processing receipt.
    pub fn acknowledged(&mut self, input: &Input) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.stamp, &input.owner) {
            return Err(Error::Stale);
        }
        if let Some(i) = self.processing.iter().position(|p| p.input == *input) {
            self.processing.swap_remove(i);
            return Ok(());
        }
        let r = self
            .flows
            .iter_mut()
            .flatten()
            .find(|r| r.receipt.as_ref().is_some_and(|p| p.id == *input))
            .ok_or(Error::Stale)?;
        if r.receipt.as_ref().is_none_or(|p| !p.ready || !p.issued) {
            return Err(Error::NotReady);
        }
        r.receipt = None;
        Ok(())
    }
    /// The native host really retired this original processing/ACK action after
    /// cancellation or physical source close. It must still drain/close any
    /// admitted original MQ suffix before calling this method.
    pub fn processing_retired(&mut self, input: &Input) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.stamp, &input.owner) {
            return Err(Error::Stale);
        }
        if let Some(i) = self.processing.iter().position(|p| p.input == *input) {
            let index = self.index(&self.processing[i].flow)?;
            if !self.flows[index].as_ref().is_some_and(|r| r.closing) {
                return Err(Error::NotReady);
            }
            self.processing.swap_remove(i);
            return Ok(());
        }
        let r = self
            .flows
            .iter_mut()
            .flatten()
            .find(|r| r.receipt.as_ref().is_some_and(|p| p.id == *input))
            .ok_or(Error::Stale)?;
        if !r.closing {
            return Err(Error::NotReady);
        }
        r.receipt = None;
        Ok(())
    }
    /// Next exact close/processing/socket effect. Taking it grants no IO success.
    pub fn effect(&mut self) -> Option<Effect<'_>> {
        for r in self.flows.iter_mut().flatten() {
            if r.closing && !r.peer_closed && !r.close_issued {
                r.close_issued = true;
                return Some(Effect::Close {
                    flow: r.flow.clone(),
                });
            }
            if let Some(dns) = &mut r.dns {
                if dns.cancelling && !dns.cancel_issued {
                    dns.cancel_issued = true;
                    return Some(Effect::DnsCancel {
                        job: dns.id.clone(),
                    });
                }
                if !r.closing && !dns.issued {
                    dns.issued = true;
                    return Some(Effect::DnsQuery {
                        flow: r.flow.clone(),
                        job: dns.id.clone(),
                        packet: &dns.query,
                        expires: MonoInstant(r.receipt.as_ref()?.expires),
                    });
                }
            }
            if !r.closing
                && let Some(input) = &mut r.receipt
                && input.ready
                && !input.issued
            {
                input.issued = true;
                return Some(Effect::Processed {
                    flow: r.flow.clone(),
                    input: input.id.clone(),
                });
            }
        }
        if self.stopping {
            if !self.source_close_issued
                && let Some(source) = &self.source
            {
                self.source_close_issued = true;
                return Some(Effect::CloseSource {
                    source: source.clone(),
                });
            }
            if !self.tun_close_issued
                && let Some(tun) = &self.tun
            {
                self.tun_close_issued = true;
                return Some(Effect::CloseTun { tun: tun.clone() });
            }
        }
        None
    }
    fn debts(&self, flow: &Flow) -> bool {
        if self.processing.iter().any(|p| p.flow == *flow) {
            return true;
        }
        if self
            .flows
            .iter()
            .flatten()
            .any(|r| r.flow == *flow && r.receipt.as_ref().is_some_and(|p| p.issued))
        {
            return true;
        }
        self.tun_queue
            .iter()
            .chain(self.peer_queue.iter())
            .any(|p| p.flow == *flow)
    }
    /// Supply a real nondecreasing caller-clock sample. Expiry requests native
    /// close, and NAT quarantine starts only after actual peer/IO debt retirement.
    pub fn advance(&mut self, now: MonoInstant) -> Result<(), Error> {
        let now = self.time(now)?;
        for i in 0..self.flows.len() {
            if self.flows[i].as_ref().is_some_and(|r| {
                !r.closing
                    && (self
                        .processing
                        .iter()
                        .any(|p| p.flow == r.flow && now >= p.expires)
                        || now >= r.idle
                        || r.receipt.as_ref().is_some_and(|p| now >= p.expires)
                        || self
                            .tun_queue
                            .iter()
                            .chain(self.peer_queue.iter())
                            .any(|p| p.flow == r.flow && now >= p.expires))
            }) {
                self.close_index(i, Some(Error::Deadline));
            }
            let ready = self.flows[i].as_ref().is_some_and(|r| {
                r.closing && r.peer_closed && r.dns.is_none() && !self.debts(&r.flow)
            });
            if ready {
                let r = self.flows[i].as_mut().ok_or(Error::Stale)?;
                r.receipt = None;
                if r.reuse.is_none() {
                    r.reuse = Some(
                        now.checked_add(self.limits.quarantine)
                            .ok_or(Error::Overflow)?,
                    );
                }
                if r.reported && r.reuse.is_some_and(|t| now >= t) {
                    self.flows[i] = None;
                }
            }
        }
        Ok(())
    }
    /// Earliest original idle/input/quarantine target, never reset by IO retries.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonoInstant> {
        let flow = self.flows.iter().flatten().flat_map(|r| {
            let main = if r.closing { r.reuse } else { Some(r.idle) };
            main.into_iter()
                .chain(r.receipt.as_ref().filter(|_| !r.closing).map(|p| p.expires))
        });
        let output = self
            .tun_queue
            .iter()
            .chain(self.peer_queue.iter())
            .filter(|p| {
                self.flows
                    .iter()
                    .flatten()
                    .any(|r| r.flow == p.flow && !r.closing)
            })
            .map(|p| p.expires);
        let processing = self
            .processing
            .iter()
            .filter(|p| {
                self.flows
                    .iter()
                    .flatten()
                    .any(|r| r.flow == p.flow && !r.closing)
            })
            .map(|p| p.expires);
        flow.chain(output).chain(processing).min().map(MonoInstant)
    }
    /// Actual physically settled original flow event, once. A memory-only NAT
    /// tombstone remains until the caller advances its configured reuse deadline.
    pub fn next_closed(&mut self) -> Option<Closed> {
        for i in 0..self.flows.len() {
            let Some(r) = self.flows[i].as_ref() else {
                continue;
            };
            if r.closing && r.peer_closed && r.dns.is_none() && !r.reported && !self.debts(&r.flow)
            {
                let r = self.flows[i].as_mut()?;
                r.reported = true;
                return Some(Closed {
                    flow: r.flow.clone(),
                    failure: r.failure,
                });
            }
        }
        None
    }
    /// Request all original source closes; no clock or fabricated receipt needed.
    pub fn shutdown(&mut self) {
        self.stopping = true;
        for i in 0..self.flows.len() {
            if self.flows[i].is_some() {
                self.close_index(i, None);
            }
        }
    }
    /// Whether this untouched owner may bind to a new native scheduling epoch.
    /// Quiescence alone is insufficient: retired sources, sampled time and even
    /// fully expired flow history must never acquire a replacement time origin.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.next == 0
            && self.last.is_none()
            && self.source.is_none()
            && self.tun.is_none()
            && self.flows.iter().all(Option::is_none)
            && self.processing.is_empty()
            && self.tun_queue.is_empty()
            && self.peer_queue.is_empty()
            && self.queued_bytes == 0
            && !self.stopping
            && !self.source_close_issued
            && !self.tun_close_issued
    }
    /// Actual IO quiescence, separate from retained memory-only NAT quarantine.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.processing.is_empty()
            && self.source.is_none()
            && self.tun.is_none()
            && self.tun_queue.is_empty()
            && self.peer_queue.is_empty()
            && self
                .flows
                .iter()
                .flatten()
                .all(|r| r.peer_closed && r.dns.is_none())
    }
}
