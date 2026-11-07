use crate::*;
use zeroize::Zeroizing;
/// Canonical new REGISTER. Section has no NUL; one terminal NUL is appended.
/// Addresses are exact producer-native entries, not inferred portable endpoints.
#[derive(Clone, Copy)]
pub struct RegistrationRequest<'a> {
    /// Requested callbacks, retaining raw flag bits.
    pub flags: u8,
    /// Original IP protocol selector.
    pub protocol: u8,
    /// Exact original packed native bindings, duplicates preserved.
    pub addresses: ipc::Addresses<'a>,
    /// Caller-selected configuration section, without NUL.
    pub section: &'a [u8],
}
/// One actual original notification view. Address IDs link caller-owned appctx;
/// extracting these bytes/class does not prove mapping or connection success.
pub struct Notification<'a, 'id> {
    /// Original registration.
    pub session: Session<'id>,
    /// Actual original source.
    pub epoch: Epoch<'id>,
    /// Original receive ordinal, checked and never reused.
    pub ordinal: u64,
    /// Actual service message and untouched producer-native bytes.
    pub response: ipc::Response<'a>,
    /// Original add allocation or matched removal allocation.
    pub address_id: Option<AddressId<'id>>,
    /// Original class of a removed allocation, if any.
    pub removed_class: Option<ipc::AddressClass>,
}
impl fmt::Debug for Notification<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatNotification")
            .field("session", &self.session)
            .field("epoch", &self.epoch)
            .field("ordinal", &self.ordinal)
            .field("address_id", &self.address_id)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}
/// Single original zeroizing notification owner. Source retirement can transfer
/// an unreleased actual callback here without forging a fresh-epoch callback.
pub struct OwnedNotification<'id> {
    frame: OwnedFrame,
    session: Session<'id>,
    epoch: Epoch<'id>,
    profile: ipc::Profile,
    ordinal: u64,
    id: Option<AddressId<'id>>,
    removed_class: Option<ipc::AddressClass>,
}
impl fmt::Debug for OwnedNotification<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatOwnedNotification")
            .field("session", &self.session)
            .field("epoch", &self.epoch)
            .field("ordinal", &self.ordinal)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}
impl<'id> OwnedNotification<'id> {
    /// Borrow the actual original callback, including after its source retired.
    pub fn view(&self) -> Result<Notification<'_, 'id>, Error> {
        Ok(Notification {
            session: self.session,
            epoch: self.epoch,
            ordinal: self.ordinal,
            response: ipc::Response::decode(self.frame.bytes(), self.profile)?,
            address_id: self.id,
            removed_class: self.removed_class,
        })
    }
}
/// One actual native/local observation; Submitted is never a registration ACK.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Actual original source/callback/address retirement returns bounded preallocated owners without a new fallible allocation after physical close"
)]
pub enum Progress<'id> {
    /// Actual original attachment.
    Connected(Session<'id>, Epoch<'id>),
    /// Actual immutable FIFO admission.
    Queued(Session<'id>, Epoch<'id>, WriteId<'id>, Command),
    /// Whole local write only; reverse/STUN/global remain unacknowledged.
    Written(Session<'id>, Epoch<'id>, WriteId<'id>, Command, usize),
    /// Actual original native bytes.
    Activity {
        /// Actual bytes read from the original MQ.
        read: usize,
        /// Actual bytes written to the original MQ.
        written: usize,
    },
    /// Actual retained notification, viewable until release/close.
    Notification {
        /// Original registration allocation.
        session: Session<'id>,
        /// Actual original MQ epoch.
        epoch: Epoch<'id>,
        /// Original retained callback ordinal.
        ordinal: u64,
    },
    /// An expired unexposed write was removed; original session remains live.
    WriteExpired(WriteEnd<'id>),
    /// Physical original source retired before this observation.
    Ended(End<'id>),
    /// Actual preattachment failure, before any write exposure.
    Retry(stdio::Error, Duration),
    /// Complete RX retained while allocation awaits finite retry/deadline.
    Capacity(Session<'id>, Epoch<'id>),
    /// Caller observation deadline only.
    WaitDeadline,
    /// Original terminal event already delivered.
    Closed,
}
/// Original registration, bounded cache and one retained zeroizing notification.
/// No automatic reconnect, config re-read, helper, clock replacement or replay.
pub struct Registration<'id> {
    io: io::Io<'id>,
    profiles: Profiles,
    snapshot: OwnedFrame,
    limits: Limits,
    addresses: Vec<AddressEntry<'id>>,
    next_address: u64,
    ordinal: u64,
    held: Option<OwnedNotification<'id>>,
}
impl<'id> Registration<'id> {
    /// Encode a new canonical REGISTER, without opening a socket or task. The
    /// original snapshot and selected CLIENT configuration stay fixed for its life.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        request: RegistrationRequest<'_>,
        profiles: Profiles,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        if request.section.contains(&0) || request.section.len() >= u16::MAX as usize {
            return Err(Fault::InvalidInput.into());
        }
        let mut section = Zeroizing::new(Vec::new());
        section
            .try_reserve_exact(request.section.len() + 1)
            .map_err(|_| Fault::Capacity)?;
        section.extend_from_slice(request.section);
        section.push(0);
        let frame = encoded(
            ipc::Request::Register {
                flags: request.flags,
                protocol: request.protocol,
                addresses: request.addresses,
                section: &section,
            },
            profiles.request,
        )?;
        Self::from_wire(instance, source, frame.bytes(), profiles, deadlines, limits)
    }
    /// Preserve one exact already-produced REGISTER frame, including section tails,
    /// native sockaddr padding and length bytes. No normalization/re-encoding occurs.
    pub fn from_wire(
        instance: &'id Instance,
        source: EndpointSource,
        register: &[u8],
        profiles: Profiles,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        let ipc::Request::Register { flags, .. } =
            ipc::Request::decode(register, profiles.request)?
        else {
            return Err(Fault::InvalidInput.into());
        };
        if flags & ipc::ADDRESSES != 0 && limits.addresses == 0 {
            return Err(Fault::Capacity.into());
        }
        limits.validate()?;
        if register.len() > limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        let snapshot = OwnedFrame::copy_from(register)?;
        let first = OwnedFrame::copy_from(register)?;
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(limits.addresses)
            .map_err(|_| Fault::Capacity)?;
        let io = io::Io::new(
            instance,
            source,
            first,
            Command::Register,
            deadlines,
            limits,
        )?;
        Ok(Self {
            io,
            profiles,
            snapshot,
            limits,
            addresses,
            next_address: 0,
            ordinal: 0,
            held: None,
        })
    }
    /// Default live endpoint is actual `nat`; snapshots once before native admission.
    pub fn from_live(
        instance: &'id Instance,
        live: LiveConfiguration,
        resolution: resolution::SharedResolution,
        request: RegistrationRequest<'_>,
        profiles: Profiles,
        deadlines: Deadlines,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::new(
            instance,
            nat_source(live, resolution),
            request,
            profiles,
            deadlines,
            limits,
        )
    }
    /// Original caller allocation; no wire RID exists.
    pub const fn session(&self) -> Session<'id> {
        self.io.session
    }
    /// Original initial request identity, before/after actual native admission.
    pub fn initial_write(&self) -> WriteId<'id> {
        self.io.initial_id()
    }
    /// Bounded original pending writes, including prepared but not native queued.
    pub fn pending_writes(&self) -> usize {
        self.io.pending_writes()
    }
    /// Whether the supplied actual epoch is still this live original source.
    pub fn is_current(&self, epoch: Epoch<'id>) -> bool {
        !self.io.closed && self.io.epoch == Some(epoch)
    }
    /// Actual attached original epoch, retained as historical metadata after loss.
    pub const fn epoch(&self) -> Option<Epoch<'id>> {
        self.io.epoch
    }
    /// Only actual whole REGISTER local-write state, never service acceptance.
    pub fn registered_submission(&self) -> Submission {
        self.io.initial()
    }
    /// Exact original snapshot, never reconstructed using live configuration.
    pub fn registration_bytes(&self) -> &[u8] {
        self.snapshot.bytes()
    }
    /// Original borrowed REGISTER fields, including original raw section bytes.
    pub fn registration(&self) -> Result<ipc::Request<'_>, Error> {
        Ok(ipc::Request::decode(
            self.snapshot.bytes(),
            self.profiles.request,
        )?)
    }
    /// Original shared clock, not an invented replacement domain.
    pub fn clock(&self) -> Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.io.clock.clone()
    }
    /// Actual source closed flag. Closed cache data supplies no current authority.
    pub const fn closed(&self) -> bool {
        self.io.closed
    }
    /// Preserve one official follow-up request; REGISTER cannot be replaced on a
    /// live session. All operations keep their original finite send deadline.
    pub fn submit(&mut self, request: ipc::Request<'_>, until: u64) -> Result<WriteId<'id>, Error> {
        let command = match request {
            ipc::Request::Register { .. } => return Err(Fault::Conflict.into()),
            ipc::Request::Stun { .. } => Command::Stun,
            ipc::Request::Reverse { .. } => Command::Reverse,
            ipc::Request::AddGlobal { .. } => Command::AddGlobal,
        };
        let frame = encoded(request, self.profiles.request)?;
        self.io.admit(frame, command, until)
    }
    /// Submit already-produced exact bytes with the selected request ABI.
    pub fn submit_raw(&mut self, frame: &[u8], until: u64) -> Result<WriteId<'id>, Error> {
        let command = match ipc::Request::decode(frame, self.profiles.request)? {
            ipc::Request::Register { .. } => return Err(Fault::Conflict.into()),
            ipc::Request::Stun { .. } => Command::Stun,
            ipc::Request::Reverse { .. } => Command::Reverse,
            ipc::Request::AddGlobal { .. } => Command::AddGlobal,
        };
        self.io.admit(OwnedFrame::copy_from(frame)?, command, until)
    }
    /// Original STUN datagram forwarding; no STUN transaction authenticity is inferred.
    pub fn stun(
        &mut self,
        sender: ipc::RawAddress<'_>,
        payload: &[u8],
        until: u64,
    ) -> Result<WriteId<'id>, Error> {
        self.submit(ipc::Request::Stun { sender, payload }, until)
    }
    /// Official IPv4 helper/reverse proposal, without a fabricated completion reply.
    pub fn reverse(
        &mut self,
        local: ipc::RawAddress<'_>,
        remote: ipc::RawAddress<'_>,
        until: u64,
    ) -> Result<WriteId<'id>, Error> {
        self.submit(ipc::Request::Reverse { local, remote }, until)
    }
    /// Official global-address bytes and active native length quirk; no mapping ACK.
    pub fn add_global(&mut self, address: &[u8], until: u64) -> Result<WriteId<'id>, Error> {
        self.submit(ipc::Request::AddGlobal { address }, until)
    }
    /// Exact byte exposure while that original write remains pending. Completed
    /// local writes are represented by their original Written event, not retained forever.
    pub fn submission(&self, write: WriteId<'id>) -> Result<Submission, Error> {
        self.io.submission(write)
    }
    fn ended(&mut self, source: SourceEnd<'id>) -> End<'id> {
        End {
            source,
            notification: self.held.take(),
            addresses: std::mem::take(&mut self.addresses),
        }
    }
    /// Cancel one original unexposed queued write, or physically close the whole
    /// registration when initial/exposed. No wire cancellation or ACK is invented.
    pub fn cancel_write(&mut self, write: WriteId<'id>) -> Result<Cancel<'id>, Error> {
        match self.io.cancel(write)? {
            Ok(end) => Ok(Cancel::Unsent(end)),
            Err(source) => Ok(Cancel::SessionClosed(self.ended(source))),
        }
    }
    /// Actual whole registration physical close, independent of clock progress.
    pub fn close(&mut self) -> Option<End<'id>> {
        self.io.close(Cause::Closed, None).map(|s| self.ended(s))
    }
    /// Actual official unregister/cancel behavior: physically close original MQ.
    pub fn cancel(&mut self) -> Option<End<'id>> {
        self.io.close(Cause::Cancelled, None).map(|s| self.ended(s))
    }
    /// Exact C test_address semantics: native length/bytes (padding/port/scope too),
    /// not canonical IP equality. A retired session always refuses current plausibility.
    pub fn test_address(&self, address: ipc::RawAddress<'_>) -> Result<bool, Error> {
        if self.io.closed {
            return Err(Fault::Closed.into());
        }
        if address.profile() != self.profiles.response
            || matches!(address.address(), ipc::Address::Unix(_))
        {
            return Err(Fault::InvalidInput.into());
        }
        Ok(self.addresses.iter().any(|row| {
            row.len == address.as_bytes().len() && row.raw[..row.len] == *address.as_bytes()
        }))
    }
    /// Current original address rows; duplicates have separate IDs/app contexts.
    pub fn addresses(&self) -> impl Iterator<Item = &AddressEntry<'id>> {
        self.addresses.iter().filter(|_| !self.io.closed)
    }
    /// Current original allocation only; old IDs never bind to a future registration.
    pub fn address(&self, id: AddressId<'id>) -> Result<&AddressEntry<'id>, Error> {
        if self.io.closed {
            return Err(Fault::Closed.into());
        }
        self.addresses
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| Fault::Stale.into())
    }
    /// Borrow the one original notification; no extra path/address copy occurs here.
    pub fn notification(&self) -> Result<Option<Notification<'_, 'id>>, Error> {
        if self.io.closed {
            return Ok(None);
        }
        let Some(held) = &self.held else {
            return Ok(None);
        };
        Ok(Some(held.view()?))
    }
    /// Release only the current retained callback frame. It never removes an address
    /// allocation or fabricates acknowledgement/credit on the wire. An expired
    /// long-lived input guard closes the source first and keeps the held frame
    /// for its original End; repeated release cannot consume that retained debt.
    pub fn release_notification(&mut self) -> Result<(), Error> {
        if self.held.is_none() {
            return Err(Fault::NotReady.into());
        }
        self.io.release_input()?;
        drop(self.held.take());
        Ok(())
    }
    fn receive(&mut self) -> Result<Option<Progress<'id>>, Error> {
        let epoch = self.io.epoch.ok_or(Fault::Stale)?;
        let frame = match self.io.copy_input() {
            Ok(frame) => frame,
            Err(Fault::Capacity) => {
                self.io.pause_capacity()?;
                return Ok(Some(Progress::Capacity(self.io.session, epoch)));
            }
            Err(e) => return Err(e.into()),
        };
        let response = ipc::Response::decode(frame.bytes(), self.profiles.response)?;
        let mut id = None;
        let mut removed_class = None;
        match response {
            ipc::Response::AddressChange {
                add_remove,
                class,
                address,
            } => {
                if add_remove == 1 {
                    if self.addresses.len() == self.limits.addresses {
                        return Err(Fault::Capacity.into());
                    }
                    let next = self.next_address.checked_add(1).ok_or(Fault::Overflow)?;
                    let token = AddressId {
                        brand: self.io.session.brand,
                        serial: next,
                    };
                    let mut raw = Zeroizing::new([0; 28]);
                    raw[..address.as_bytes().len()].copy_from_slice(address.as_bytes());
                    self.addresses.push(AddressEntry {
                        id: token,
                        epoch,
                        class,
                        raw,
                        len: address.as_bytes().len(),
                        profile: self.profiles.response,
                    });
                    self.next_address = next;
                    id = Some(token);
                } else {
                    let index = self
                        .addresses
                        .iter()
                        .rposition(|old| {
                            old.len == address.as_bytes().len()
                                && old.raw[..old.len] == *address.as_bytes()
                        })
                        .ok_or(Fault::Stale)?;
                    let old = self.addresses.remove(index);
                    id = Some(old.id);
                    removed_class = Some(old.class);
                }
            }
            ipc::Response::Reverse { .. } => {}
        }
        self.ordinal = self.ordinal.checked_add(1).ok_or(Fault::Overflow)?;
        self.held = Some(OwnedNotification {
            session: self.io.session,
            epoch,
            profile: self.profiles.response,
            frame,
            ordinal: self.ordinal,
            id,
            removed_class,
        });
        Ok(Some(Progress::Notification {
            session: self.io.session,
            epoch,
            ordinal: self.ordinal,
        }))
    }
    /// Poll actual native ownership. A held callback applies backpressure to RX;
    /// original deadlines, pending TX and independent physical close still progress.
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<tokio::time::Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        let step = match self.io.poll(cx, wait, self.held.is_none()) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(step) => step,
        };
        self.progress(step)
    }
    fn progress(&mut self, step: io::Step<'id>) -> Poll<Result<Progress<'id>, Error>> {
        let progress = match step {
            io::Step::Connected(epoch) => Progress::Connected(self.io.session, epoch),
            io::Step::Queued(w, e, c) => Progress::Queued(self.io.session, e, w, c),
            io::Step::Written(w, e, c, n) => Progress::Written(self.io.session, e, w, c, n),
            io::Step::Activity(read, written) => Progress::Activity { read, written },
            io::Step::Retired(end) => Progress::WriteExpired(end),
            io::Step::Ended(source) => Progress::Ended(self.ended(source)),
            io::Step::Retry(error, delay) => Progress::Retry(error, delay),
            io::Step::WaitDeadline => Progress::WaitDeadline,
            io::Step::Closed => Progress::Closed,
            io::Step::Input => match self.receive() {
                Ok(Some(progress)) => return Poll::Ready(Ok(progress)),
                Ok(None) => return Poll::Pending,
                Err(error) => {
                    let source = self
                        .io
                        .close(Cause::Error(error), None)
                        .ok_or(Fault::Stale)?;
                    return Poll::Ready(Ok(Progress::Ended(self.ended(source))));
                }
            },
        };
        Poll::Ready(Ok(progress))
    }
    /// Check/register only original native deadlines and deferred source debt.
    /// This performs no clock sample or socket read/write. Only a real original
    /// Ended/WriteExpired event is returned; idle/already-ended is Pending, not a
    /// fabricated wait or repeated terminal event. Ordinary poll shares the same
    /// guard and event conversion, so consuming it here cannot duplicate it.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<tokio::time::Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        match self.io.poll_native_guard(cx, wait) {
            Poll::Ready(step) => self.progress(step),
            Poll::Pending => Poll::Pending,
        }
    }
    /// Public poll closes the original MQ on every unexpected local failure,
    /// preserving the actual cause and unreleased original callback in End.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<tokio::time::Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        match self.poll_inner(cx, wait) {
            Poll::Ready(Err(error)) if !self.io.closed => {
                let end = self
                    .io
                    .close(Cause::Error(error), None)
                    .ok_or(Fault::Stale)?;
                Poll::Ready(Ok(Progress::Ended(self.ended(end))))
            }
            other => other,
        }
    }
    /// Canceling this waiting future does not cancel/recreate registration or lose
    /// the original callback/frame/write cursor. Explicit close/drop owns cancellation.
    pub async fn drive(
        &mut self,
        wait: Option<tokio::time::Instant>,
    ) -> Result<Progress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, wait)).await
    }
}
impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let _end = self.io.close(Cause::Closed, None);
    }
}
