//! Actual PEERSTORE monitor/STORE sources and bounded public HELLO snapshots.
//! These public addresses are dial candidates, never authenticated peer owners.
type Address<'a> = ([u8; 32], &'a [u8]);
use crate::{Error, Limits, budget::Bound};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::EddsaPublicKey;
use gnunet_hello::Hello;
use gnunet_peerstore_client_host as ps;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
use std::{
    future::Future,
    sync::Arc,
    task::{Context, Poll},
};
const SUBSYSTEM: &[u8] = b"peerstore";
const KEY: &[u8] = b"peerstore-peer-hello-uri";
pub(crate) struct Record {
    pub peer: [u8; 32],
    pub expiration: u64,
    pub message: Vec<u8>,
    pub block: Vec<u8>,
    pub url: Vec<u8>,
    pub next_address: usize,
    pub cache_pending: bool,
    pub store_pending: bool,
}
pub(crate) struct Hint {
    pub peer: [u8; 32],
    pub expiration: u64,
    pub uri: Vec<u8>,
}
pub(crate) enum Step<'id> {
    Monitor(ps::Progress<'id>),
    Store(ps::Progress<'id>),
    Observed,
    Invalid(Error),
}
struct Store<'id> {
    operation: ps::Operation<'id>,
    bound: Bound,
    cancelled: bool,
}
pub(crate) struct Discovery<'id> {
    monitor: Option<ps::Client<'id>>,
    writer: Option<ps::Client<'id>>,
    operation: Option<ps::Operation<'id>>,
    bound: Option<Bound>,
    input: Option<Bound>,
    store: Option<Store<'id>>,
    credit: bool,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    pub records: Vec<Record>,
    pub hints: Vec<Hint>,
    pub hint_first: bool,
    scratch: Vec<u8>,
    closed: bool,
    first: bool,
    deferred: Option<ps::Progress<'id>>,
}
impl<'id> Discovery<'id> {
    pub fn new(
        monitor: &'id mut ps::Instance,
        writer: &'id mut ps::Instance,
        source: EndpointSource,
        clock: Arc<dyn RuntimeClock>,
        limits: Limits,
        enabled: bool,
    ) -> Result<Self, Error> {
        let (monitor, writer) = if enabled {
            let second = source.duplicate()?;
            (
                Some(ps::Client::new_monitor(monitor, source, limits.peerstore)?),
                Some(ps::Client::new(writer, second, limits.peerstore)?),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            monitor,
            writer,
            operation: None,
            bound: None,
            input: None,
            store: None,
            credit: false,
            clock,
            limits,
            records: Vec::new(),
            hints: Vec::new(),
            hint_first: true,
            scratch: buffer(limits.hello.maximum_address_bytes)?,
            closed: false,
            first: false,
            deferred: None,
        })
    }
    pub fn observe(
        &mut self,
        bytes: &[u8],
        claimed: Option<[u8; 32]>,
        now: u64,
        offer: bool,
    ) -> Result<bool, Error> {
        let hello = Hello::parse_message(
            bytes,
            claimed.map(EddsaPublicKey::from_bytes),
            &mut self.scratch,
            self.limits.hello,
        )?;
        hello.verify_at(
            self.limits.pils_profile.hello(),
            AbsoluteTime::from_micros(now),
        )?;
        let peer = *hello.peer().as_bytes();
        if claimed.is_some_and(|p| p != peer) {
            return Err(Fault::Authentication.into());
        }
        let expiration = hello.expiration().as_micros();
        let old = self.records.iter().position(|r| r.peer == peer);
        if old.is_some_and(|i| self.records[i].expiration >= expiration) {
            return Ok(false);
        }
        let mut message = buffer(hello.message_len()?)?;
        hello.encode_message(&mut message)?;
        let mut block = buffer(hello.block_len()?)?;
        hello.encode_block(&mut block)?;
        let mut url = buffer(hello.url_len()?)?;
        hello.write_url(&mut url)?;
        let new_bytes = message
            .capacity()
            .checked_add(block.capacity())
            .and_then(|n| n.checked_add(url.capacity()))
            .ok_or(Fault::Overflow)?;
        let used = self
            .records
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != old)
            .try_fold(new_bytes, |n, (_, r)| {
                n.checked_add(r.message.capacity())
                    .and_then(|n| n.checked_add(r.block.capacity()))
                    .and_then(|n| n.checked_add(r.url.capacity()))
                    .ok_or(Fault::Overflow)
            })?;
        let used = self.hints.iter().try_fold(used, |n, h| {
            n.checked_add(h.uri.capacity()).ok_or(Fault::Overflow)
        })?;
        if used > self.limits.address_bytes
            || (old.is_none()
                && self
                    .records
                    .len()
                    .checked_add(self.hints.len())
                    .ok_or(Fault::Overflow)?
                    >= self.limits.addresses)
        {
            return Err(Fault::Capacity.into());
        }
        let record = Record {
            peer,
            expiration,
            message,
            block,
            url,
            next_address: 0,
            cache_pending: true,
            store_pending: offer && self.writer.is_some(),
        };
        if let Some(i) = old {
            self.records[i] = record;
        } else {
            self.records.try_reserve(1).map_err(|_| Fault::Capacity)?;
            self.records.push(record);
        }
        Ok(true)
    }
    /// Called only after this same immutable RESULT passed the original DHT
    /// BLOCK/path/source checks. HELLO's own key may differ from the relay peer.
    /// Each new real observation may request a new candidate validation; no old
    /// exposed APPLICATION frame or processing result is reconstructed.
    pub fn observe_block(&mut self, payload: &[u8], now: u64) -> Result<(), Error> {
        let hello = Hello::parse_block(payload, &mut self.scratch, self.limits.hello)?;
        hello.verify_at(
            self.limits.pils_profile.hello(),
            AbsoluteTime::from_micros(now),
        )?;
        let peer = *hello.peer().as_bytes();
        let expiration = hello.expiration().as_micros();
        if expiration <= now {
            return Ok(());
        }
        let new = hello
            .addresses()
            .filter(|a| {
                !self
                    .hints
                    .iter()
                    .any(|h| h.peer == peer && h.uri == a.as_bytes())
            })
            .count();
        let count = self
            .records
            .len()
            .checked_add(self.hints.len())
            .and_then(|n| n.checked_add(new))
            .ok_or(Fault::Overflow)?;
        if count > self.limits.addresses {
            return Err(Fault::Capacity.into());
        }
        let mut used = self.records.iter().try_fold(0usize, |n, r| {
            n.checked_add(r.message.capacity())
                .and_then(|n| n.checked_add(r.block.capacity()))
                .and_then(|n| n.checked_add(r.url.capacity()))
                .ok_or(Fault::Overflow)
        })?;
        used = self.hints.iter().try_fold(used, |n, h| {
            n.checked_add(h.uri.capacity()).ok_or(Fault::Overflow)
        })?;
        let mut staged = Vec::new();
        staged.try_reserve_exact(new).map_err(|_| Fault::Capacity)?;
        self.hints
            .try_reserve_exact(new)
            .map_err(|_| Fault::Capacity)?;
        for address in hello.addresses() {
            if self
                .hints
                .iter()
                .any(|h| h.peer == peer && h.uri == address.as_bytes())
            {
                continue;
            }
            if used
                .checked_add(address.as_bytes().len())
                .ok_or(Fault::Overflow)?
                > self.limits.address_bytes
            {
                return Err(Fault::Capacity.into());
            }
            let mut uri = buffer(address.as_bytes().len())?;
            uri.copy_from_slice(address.as_bytes());
            used = used.checked_add(uri.capacity()).ok_or(Fault::Overflow)?;
            if used > self.limits.address_bytes {
                return Err(Fault::Capacity.into());
            }
            staged.push(Hint {
                peer,
                expiration,
                uri,
            });
        }
        // All fallible preparation completed before changing old candidate state.
        for address in hello.addresses() {
            if let Some(h) = self
                .hints
                .iter_mut()
                .find(|h| h.peer == peer && h.uri == address.as_bytes())
            {
                h.expiration = h.expiration.max(expiration);
            }
        }
        self.hints.extend(staged);
        Ok(())
    }
    pub fn address(&mut self, index: usize) -> Result<Option<Address<'_>>, Error> {
        let r = self.records.get(index).ok_or(Fault::Stale)?;
        let h = Hello::parse_message(&r.message, None, &mut self.scratch, self.limits.hello)?;
        Ok(h.addresses()
            .nth(r.next_address)
            .map(|a| (r.peer, a.as_bytes())))
    }
    pub fn expire(&mut self, now: u64) {
        self.records.retain(|r| r.expiration >= now);
        self.hints.retain(|h| h.expiration > now);
    }
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.closed {
            return Ok(false);
        }
        if self.bound.as_mut().is_some_and(|b| b.poll_native(cx))
            || self.input.as_mut().is_some_and(|b| b.poll_native(cx))
        {
            if let Some(op) = self.operation.take() {
                self.monitor.as_mut().ok_or(Fault::Conflict)?.cancel(op)?;
            }
            self.bound = None;
            self.input = None;
            self.credit = false;
            return Ok(true);
        }
        if self
            .store
            .as_mut()
            .is_some_and(|s| !s.cancelled && s.bound.poll_native(cx))
        {
            // Physical retirement fences an exposed STORE; it is never replayed.
            let event = self.writer.as_mut().ok_or(Fault::Conflict)?.reconnect()?;
            if let Some(store) = self.store.as_mut() {
                store.cancelled = true;
            }
            // Preserve this original source termination before later callbacks.
            self.deferred = Some(event);
            return Ok(true);
        }
        Ok(false)
    }
    pub fn canonical_guard(&mut self, now: u64) -> Result<Option<ps::Progress<'id>>, Error> {
        if self.bound.as_ref().is_some_and(|b| now >= b.until)
            || self.input.as_ref().is_some_and(|b| now >= b.until)
        {
            if let Some(op) = self.operation.take() {
                self.monitor.as_mut().ok_or(Fault::Conflict)?.cancel(op)?;
            }
            self.bound = None;
            self.input = None;
            self.credit = false;
            return Ok(self.monitor.as_mut().and_then(ps::Client::next_event));
        }
        Ok(None)
    }
    fn prepare(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        if self.operation.is_none() && self.monitor.as_ref().is_some_and(ps::Client::is_idle) {
            let bound = Bound::new(self.clock.as_ref(), self.limits.discovery_lifetime)?;
            bound.check(self.clock.as_ref())?;
            let op = self.monitor.as_mut().ok_or(Fault::Conflict)?.monitor(
                ps::Filter {
                    peer: None,
                    subsystem: Some(SUBSYSTEM),
                    key: Some(KEY),
                },
                true,
                bound.until,
            )?;
            self.operation = Some(op);
            self.bound = Some(bound);
        }
        if self.credit
            && let Some(op) = self.operation
        {
            match self.monitor.as_mut().ok_or(Fault::Conflict)?.next(op, 1) {
                Ok(()) => self.credit = false,
                Err(ps::Error::Protocol(Fault::NotReady | Fault::WouldBlock)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if self.store.is_none()
            && self.writer.as_ref().is_some_and(ps::Client::is_idle)
            && let Some(i) = self.records.iter().position(|r| r.store_pending)
        {
            let bound = Bound::new(self.clock.as_ref(), self.limits.output_lifetime)?;
            let r = &self.records[i];
            let op = self.writer.as_mut().ok_or(Fault::Conflict)?.store(
                ps::Record {
                    peer: r.peer,
                    expiry: r.expiration,
                    subsystem: Some(SUBSYSTEM),
                    key: Some(KEY),
                    value: &r.message,
                },
                1,
                bound.until,
            )?;
            // A retained original STORE is not retried, including Unknown.
            self.records[i].store_pending = false;
            self.store = Some(Store {
                operation: op,
                bound,
                cancelled: false,
            });
        }
        Ok(())
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<'id>, Error>> {
        if self.closed {
            return match self.take_event() {
                Some(event) => Poll::Ready(Ok(Step::Store(event))),
                None => Poll::Pending,
            };
        }
        if let Some(event) = self.deferred.take() {
            return Poll::Ready(Ok(Step::Store(event)));
        }
        self.prepare()?;
        for n in 0..2 {
            let writer = (n == 0) == self.first;
            let event = {
                let Some(client) = (if writer {
                    self.writer.as_mut()
                } else {
                    self.monitor.as_mut()
                }) else {
                    continue;
                };
                let mut f = std::pin::pin!(client.drive(None));
                match f.as_mut().poll(cx) {
                    Poll::Pending => continue,
                    Poll::Ready(r) => r?,
                }
            };
            let event = match event {
                ps::Progress::Unavailable(e) => return Poll::Ready(Err(e.into())),
                event => event,
            };
            self.first = !writer;
            if writer {
                if let ps::Progress::Completed { operation, .. } = &event
                    && self
                        .store
                        .as_ref()
                        .is_some_and(|s| s.operation == *operation)
                {
                    self.store = None;
                }
                return Poll::Ready(Ok(Step::Store(event)));
            }
            match event {
                ps::Progress::Record(record) => {
                    if Some(record.operation()) != self.operation {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    self.input = None;
                    let r = record.record()?.record;
                    self.credit = true;
                    if r.subsystem != Some(SUBSYSTEM) || r.key != Some(KEY) {
                        return Poll::Ready(Err(Fault::Malformed.into()));
                    }
                    let now = self.clock.sample()?.now.as_micros();
                    let result = self.observe(r.value, Some(r.peer), now, false);
                    return Poll::Ready(Ok(match result {
                        Ok(_) => Step::Observed,
                        Err(e) => Step::Invalid(e),
                    }));
                }
                ps::Progress::Activity { read_bytes, .. } if read_bytes > 0 => {
                    if self.input.is_none() {
                        self.input =
                            Some(Bound::new(self.clock.as_ref(), self.limits.input_lifetime)?);
                    }
                    return Poll::Ready(Ok(Step::Monitor(event)));
                }
                ps::Progress::Completed { operation, .. } if Some(operation) == self.operation => {
                    self.operation = None;
                    self.bound = None;
                    self.input = None;
                    return Poll::Ready(Ok(Step::Monitor(event)));
                }
                ps::Progress::Lost { .. } => {
                    self.input = None;
                    return Poll::Ready(Ok(Step::Monitor(event)));
                }
                other => {
                    self.input = None;
                    return Poll::Ready(Ok(Step::Monitor(other)));
                }
            }
        }
        Poll::Pending
    }
    pub fn pending(&self) -> usize {
        self.monitor.as_ref().map_or(0, ps::Client::pending)
            + self.writer.as_ref().map_or(0, ps::Client::pending)
    }
    pub fn close(&mut self) -> [Result<Option<ps::Progress<'id>>, ps::Error>; 2] {
        self.closed = true;
        self.hints.clear();
        let monitor = self.monitor.as_mut().map_or(Ok(None), ps::Client::close);
        let writer = self.writer.as_mut().map_or(Ok(None), ps::Client::close);
        self.operation = None;
        self.bound = None;
        self.input = None;
        self.store = None;
        [monitor, writer]
    }
    pub fn take_event(&mut self) -> Option<ps::Progress<'id>> {
        self.deferred
            .take()
            .or_else(|| self.monitor.as_mut().and_then(ps::Client::next_event))
            .or_else(|| self.writer.as_mut().and_then(ps::Client::next_event))
    }
}
pub(crate) fn buffer(n: usize) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    b.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    b.resize(n, 0);
    Ok(b)
}
