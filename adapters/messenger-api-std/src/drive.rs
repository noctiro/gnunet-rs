//! Actual bounded crypto/provider execution and domain-to-native work transfer.
use crate::{clock::Span, types::*, *};
use domain::{OperationPhase, RoomPhase, Work};
use gnunet_types::Error as Fault;
use wire::{body::Body, padding};
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    fn binding(work: &Work<'a>) -> Binding<'a> {
        match work {
            Work::Wire { binding, .. }
            | Work::Sign { binding, .. }
            | Work::SharedKey { binding }
            | Work::EphemeralKey { binding, .. }
            | Work::EpochRecord { binding, .. } => *binding,
        }
    }
    pub(crate) fn free_jobs(&self) -> usize {
        self.limits
            .operations
            .saturating_sub(self.leases.len().saturating_add(self.reservations))
    }
    pub(crate) fn reset_decryption(&mut self) {
        self.decrypt_remaining = self
            .rooms
            .iter()
            .map(|r| self.core.deferred(r.room).map(|v| v.count()).unwrap_or(0))
            .fold(0, usize::saturating_add);
    }
    pub(crate) fn observe_rooms(&mut self) -> Result<(), Error> {
        let mut keys_changed = false;
        for index in 0..self.rooms.len() {
            let room = self.rooms[index].room;
            let member = self.core.local_member(room)?;
            self.rooms[index].member = member;
            if let Some(member) = member {
                let public = *self.core.member_public(member)?;
                if let Some(identity) = self.rooms[index].pending_identity {
                    let selected = self.signer(identity)?;
                    if self.signers[selected].public == public {
                        if let Some(key) = self.rooms[index].replacement_key.take() {
                            let original = self.rooms[index]
                                .identity_operation
                                .ok_or(Fault::Conflict)?;
                            let span = self
                                .leases
                                .iter()
                                .find(|l| l.operation == original)
                                .ok_or(Fault::StaleGeneration)?
                                .span;
                            let source = self.rooms[index].source.ok_or(Fault::StaleGeneration)?;
                            if let Err(error) =
                                self.store_recipient(room, source, identity, &key, span)
                            {
                                if matches!(
                                    error,
                                    Error::Local(Fault::WouldBlock | Fault::Capacity)
                                        | Error::Native(native::Error::Protocol(
                                            Fault::WouldBlock | Fault::Capacity
                                        ))
                                ) {
                                    self.rooms[index].replacement_key = Some(key);
                                    continue;
                                }
                                return Err(error);
                            }
                            let mut hpke = [0; 36];
                            key.public_key().encode_hpke(&mut hpke)?;
                            self.rooms[index].recipient_public = Some(hpke);
                            self.core.retain_recipient_key(member, key)?;
                            keys_changed = true;
                        }
                        self.rooms[index].identity_operation = None;
                        self.rooms[index].signer = identity;
                        self.rooms[index].pending_identity = None;
                    }
                }
                if let Some(join) = self.rooms[index].join.as_ref() {
                    let matching = self.core.members(room)?.any(|(s, _, id, phase)| {
                        s == member && id == join.id && phase == domain::SessionPhase::Active
                    });
                    if matching && self.core.joined(room)? {
                        let span = join.span;
                        if let Some(key) = self.rooms[index]
                            .join
                            .as_mut()
                            .and_then(|j| j.recipient.take())
                        {
                            let source = self.rooms[index].source.ok_or(Fault::StaleGeneration)?;
                            let identity = self.rooms[index].signer;
                            if let Err(error) =
                                self.store_recipient(room, source, identity, &key, span)
                            {
                                if matches!(
                                    error,
                                    Error::Local(Fault::WouldBlock | Fault::Capacity)
                                        | Error::Native(native::Error::Protocol(
                                            Fault::WouldBlock | Fault::Capacity
                                        ))
                                ) {
                                    self.rooms[index]
                                        .join
                                        .as_mut()
                                        .ok_or(Fault::Conflict)?
                                        .recipient = Some(key);
                                    continue;
                                }
                                return Err(error);
                            }
                            self.core.retain_recipient_key(member, key)?;
                            keys_changed = true;
                        }
                        self.rooms[index].join = None;
                    }
                }
            }
        }
        if let Some(identity) = self.changing
            && self
                .rooms
                .iter()
                .all(|r| r.source.is_none() || r.pending_identity.is_none() && r.signer == identity)
        {
            self.selected = identity;
            self.changing = None;
        }
        if keys_changed {
            self.reset_decryption();
        }
        Ok(())
    }
    fn initialize_room(&mut self, index: usize, now: u64) -> Result<bool, Error> {
        if self.free_jobs() == 0
            || self.changing.is_some()
            || self.rooms[index].close_after.is_some()
        {
            return Ok(false);
        }
        let Some(source) = self.rooms[index].source else {
            return Ok(false);
        };
        let epoch = self.rooms[index].epoch.ok_or(Fault::StaleGeneration)?;
        if !matches!(
            self.core.phase(self.rooms[index].room)?,
            RoomPhase::Open | RoomPhase::Entered
        ) {
            return Ok(false);
        }
        let Some(join) = self.rooms[index].join.as_ref() else {
            return Ok(false);
        };
        let span = join.span;
        if span.expired(Some(now)) {
            return Err(Fault::Timeout.into());
        }
        let hpke = if self.rooms[index].member.is_none() {
            if self.rooms[index]
                .join
                .as_ref()
                .is_some_and(|j| j.recipient.is_none())
            {
                let key = crypto::EcdheSecret::generate_hpke(&mut self.entropy)?;
                if span.expired(None) {
                    return Err(Fault::Timeout.into());
                }
                let mut public = [0; 36];
                key.public_key().encode_hpke(&mut public)?;
                self.rooms[index].recipient_public = Some(public);
                self.rooms[index]
                    .join
                    .as_mut()
                    .ok_or(Fault::Conflict)?
                    .recipient = Some(key);
            }
            self.rooms[index].recipient_public.ok_or(Fault::NotReady)?
        } else {
            self.rooms[index].recipient_public.ok_or(Fault::NotReady)?
        };
        let operation = match self
            .core
            .prepare_assigned_identity(source, hpke, now, span.logical)
        {
            Ok(op) => op,
            Err(domain::Error::Protocol(Fault::NotReady | Fault::WouldBlock)) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        self.record_job(
            self.rooms[index].room,
            source,
            epoch,
            operation,
            span,
            Intent::Initialization,
        )?;
        Ok(true)
    }
    fn take_domain_work(&mut self, room: Room<'a>) -> Result<bool, Error> {
        if self.held_work.len() == self.limits.operations {
            return Ok(false);
        }
        let Some(work) = self.core.take_work(room)? else {
            return Ok(false);
        };
        let binding = Self::binding(&work);
        let l = self
            .leases
            .iter_mut()
            .find(|l| l.operation == binding.operation())
            .ok_or(Fault::StaleGeneration)?;
        if l.room != room
            || l.source != binding.source()
            || Some(l.epoch) != self.epoch
            || l.binding.is_some_and(|b| {
                b.operation() != binding.operation()
                    || b.source() != binding.source()
                    || b.message() != binding.message()
            })
        {
            return Err(Fault::StaleGeneration.into());
        }
        l.binding = Some(binding);
        self.held_work.push(work);
        Ok(true)
    }
    fn work_index(&self) -> Option<usize> {
        self.held_work
            .iter()
            .enumerate()
            .filter_map(|(index, w)| {
                let binding = Self::binding(w);
                let l = self
                    .leases
                    .iter()
                    .find(|l| l.operation == binding.operation())?;
                if matches!(w, Work::EpochRecord { .. }) && self.record_blocked {
                    return None;
                }
                if matches!(w, Work::Wire { .. }) && (self.native_blocked || self.domain_blocked) {
                    return None;
                }
                if matches!(w, Work::Wire { .. })
                    && self.leases.iter().any(|old| {
                        old.room == l.room
                            && old.serial < l.serial
                            && self.core.operation_phase(old.operation).is_ok_and(|p| {
                                !matches!(
                                    p,
                                    OperationPhase::Complete
                                        | OperationPhase::Failed
                                        | OperationPhase::Cancelled
                                )
                            })
                            && !matches!(old.exposure, Exposure::Written { .. })
                    })
                {
                    return None;
                }
                Some((index, l.serial))
            })
            .min_by_key(|(_, serial)| *serial)
            .map(|(index, _)| index)
    }
    fn execute_work(&mut self, now: u64) -> Result<bool, Error> {
        let Some(index) = self.work_index() else {
            return Ok(false);
        };
        let work = self.held_work.remove(index);
        let binding = Self::binding(&work);
        let lease = self
            .leases
            .iter()
            .position(|l| l.operation == binding.operation())
            .ok_or(Fault::StaleGeneration)?;
        let span = self.leases[lease].span;
        if span.expired(Some(now)) {
            return Err(Fault::Timeout.into());
        }
        match work {
            Work::Wire {
                encoding,
                purpose: _,
                frame,
                ..
            } => {
                if encoding != domain::Encoding::Ipc {
                    return Err(domain::Error::Permission.into());
                }
                let request = wire::Request::decode(frame.expose())?;
                let kind = native::Kind::from(request);
                let native_serial = self.next_native.checked_add(1).ok_or(Fault::Overflow)?;
                match self.native.submit_bounded(request, span.logical, span.hard) {
                    Ok(operation) => {
                        let l = &mut self.leases[lease];
                        l.native = Some(operation);
                        l.native_serial = Some(native_serial);
                        self.next_native = native_serial;
                        l.kind = Some(kind);
                        l.frame_len = frame.expose().len();
                        l.exposure = Exposure::Unsent;
                    }
                    Err(native::Error::Protocol(Fault::WouldBlock | Fault::Capacity)) => {
                        self.native_blocked = true;
                        self.held_work.insert(
                            index,
                            Work::Wire {
                                binding,
                                purpose: match kind {
                                    native::Kind::Create => domain::NativePurpose::Create,
                                    native::Kind::Destroy => domain::NativePurpose::Destroy,
                                    native::Kind::Open => domain::NativePurpose::Open,
                                    native::Kind::Entry => domain::NativePurpose::Enter,
                                    native::Kind::Close => domain::NativePurpose::Close,
                                    native::Kind::Sync => domain::NativePurpose::Sync,
                                    native::Kind::Send => domain::NativePurpose::Send,
                                    native::Kind::Get => domain::NativePurpose::Get,
                                },
                                encoding,
                                frame,
                            },
                        );
                        return Ok(false);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Work::Sign {
                kind,
                body,
                public,
                sender,
                previous,
                timestamp,
                ..
            } => {
                let signer = self
                    .signers
                    .iter()
                    .position(|s| s.public == public)
                    .ok_or(Fault::Authentication)?;
                let typed = Body::decode(kind, body.expose(), self.core.local_profile())?;
                let signed = self.buffers.first_mut().ok_or(Fault::Conflict)?;
                signed.encode_signed(
                    &self.signers[signer].secret,
                    crypto::signature::SigningHeader {
                        timestamp: gnunet_wire::official::AbsoluteTime::from_micros(timestamp),
                        sender_id: &sender,
                        previous: &previous,
                    },
                    typed,
                    self.core.local_profile(),
                    padding::Encode::Absent,
                )?;
                if span.expired(None) {
                    signed.clear();
                    return Err(Fault::Timeout.into());
                }
                let copied = domain::OwnedBytes::copy_from(signed.expose());
                signed.clear();
                let input = copied?;
                let observed = self.sample()?;
                self.core
                    .complete_signature(binding, input, padding::Decode::Absent, observed)
                    .map_err(|e| Error::Domain(e.error))?;
            }
            Work::SharedKey { .. } => {
                let key = crypto::AeadKey::generate(&mut self.entropy)?;
                if span.expired(None) {
                    return Err(Fault::Timeout.into());
                }
                let observed = self.sample()?;
                self.core.complete_shared_key(binding, key, observed)?;
                self.reset_decryption();
            }
            Work::EphemeralKey { .. } => {
                // Official epoch announcement recipient uses raw ECDHE32;
                // serialized member JOIN HPKE generation independently draws64.
                let key = crypto::EcdheSecret::generate(&mut self.entropy)?;
                if span.expired(None) {
                    return Err(Fault::Timeout.into());
                }
                let observed = self.sample()?;
                self.core.complete_ephemeral_key(binding, key, observed)?;
            }
            Work::EpochRecord { public, .. } => {
                match self.start_record_lookup(binding, public, span) {
                    Ok(()) => {}
                    Err(Error::Local(Fault::WouldBlock | Fault::Capacity)) => {
                        self.held_work
                            .insert(index, Work::EpochRecord { binding, public });
                        self.record_blocked = true;
                        return Ok(false);
                    }
                    Err(Error::Local(
                        error @ (Fault::NotReady | Fault::StaleGeneration | Fault::Authentication),
                    )) => self.core.provider_failed(binding, error.into())?,
                    Err(Error::Domain(error)) => self.core.provider_failed(binding, error)?,
                    Err(error) => return Err(error),
                }
            }
        }
        self.wake_domain();
        Ok(true)
    }
    pub(crate) fn start_close_after_write(
        &mut self,
        operation: Operation<'a>,
    ) -> Result<(), Error> {
        let Some(index) = self
            .rooms
            .iter()
            .position(|r| r.close_after == Some(operation) && r.close_child.is_none())
        else {
            return Ok(());
        };
        let room = self.rooms[index].room;
        let source = self.rooms[index].source.ok_or(Fault::StaleGeneration)?;
        let epoch = self.rooms[index].epoch.ok_or(Fault::StaleGeneration)?;
        let span = self.rooms[index].closing_span.ok_or(Fault::Conflict)?;
        let child = match self.core.close(source, span.logical) {
            Ok(op) => op,
            Err(domain::Error::Protocol(Fault::WouldBlock | Fault::Capacity)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        self.reservations = self.reservations.checked_sub(1).ok_or(Fault::Conflict)?;
        self.record_job(room, source, epoch, child, span, Intent::LeaveClose)?;
        self.rooms[index].close_child = Some(child);
        Ok(())
    }
    pub(crate) fn finish_room_closures(&mut self) -> Result<Option<Progress<'a>>, Error> {
        for i in 0..self.rooms.len() {
            let Some(child) = self.rooms[i].close_child else {
                continue;
            };
            if self.core.operation_phase(child)? != OperationPhase::Complete {
                continue;
            }
            let source = self.rooms[i].source.ok_or(Fault::StaleGeneration)?;
            match self.core.retire_room_lease(source, child) {
                Ok(()) => {}
                Err(domain::Error::Protocol(Fault::NotReady)) => continue,
                Err(e) => return Err(e.into()),
            }
            let leave = self.rooms[i].close_after.ok_or(Fault::Conflict)?;
            let room = self.rooms[i].room;
            self.rooms[i].source = None;
            self.rooms[i].epoch = None;
            self.rooms[i].member = None;
            self.rooms[i].join = None;
            self.rooms[i].close_after = None;
            self.rooms[i].close_child = None;
            self.rooms[i].closing_span = None;
            return Ok(Some(Progress::RoomClosed {
                closing: Closing { room, leave },
                close_operation: child,
            }));
        }
        Ok(None)
    }
    fn decrypt_some(&mut self) -> Result<bool, Error> {
        if self.decrypt_remaining == 0 {
            return Ok(false);
        }
        let mut total: usize = 0;
        for r in &self.rooms {
            total = total
                .checked_add(self.core.deferred(r.room)?.count())
                .ok_or(Fault::Overflow)?;
        }
        if total == 0 {
            self.decrypt_remaining = 0;
            return Ok(false);
        }
        let mut offset = self.decrypt_cursor % total;
        self.decrypt_cursor = self.decrypt_cursor.checked_add(1).ok_or(Fault::Overflow)?;
        self.decrypt_remaining -= 1;
        let mut candidate = None;
        for r in &self.rooms {
            let count = self.core.deferred(r.room)?.count();
            if offset < count {
                candidate = self
                    .core
                    .deferred(r.room)?
                    .nth(offset)
                    .map(|(h, p)| (r.room, *h, p));
                break;
            }
            offset -= count;
        }
        let Some((room, hash, phase)) = candidate else {
            return Ok(false);
        };
        if phase != domain::MessagePhase::AwaitingEpoch {
            return Ok(false);
        }
        let scratch = self.buffers.first_mut().ok_or(Fault::Conflict)?;
        match self.core.decrypt_message(room, &hash, scratch) {
            Ok(()) => {
                self.reset_decryption();
                Ok(true)
            }
            Err(domain::Error::Protocol(
                Fault::NotReady | Fault::Authentication | Fault::InvalidInput,
            )) => Ok(false),
            Err(domain::Error::Crypto(crypto::Error::Protocol(Fault::Authentication))) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    pub(crate) fn drive_domain(&mut self, now: u64) -> Result<(), Error> {
        self.observe_rooms()?;
        self.observe_memberships();
        self.observe_subscriptions(Some(now))
            .map_err(|(_, error)| Error::Domain(error))?;
        if self.disconnecting {
            return Ok(());
        }
        self.restore_memberships(now)?;
        for _ in 0..self.limits.work_per_poll {
            if self.rooms.is_empty() || self.scan_remaining == 0 || self.domain_blocked {
                break;
            }
            self.scan_remaining -= 1;
            let i = self.room_cursor % self.rooms.len();
            self.room_cursor = self.room_cursor.checked_add(1).ok_or(Fault::Overflow)?;
            if self.rooms[i].source.is_none() {
                continue;
            }
            match self.core.advance(self.rooms[i].room, now) {
                Ok(steps) => {
                    if steps == self.limits.core.work_per_turn {
                        self.scan_remaining = self.rooms.len();
                    }
                }
                Err(domain::Error::Protocol(Fault::WouldBlock | Fault::Capacity)) => {
                    self.domain_blocked = true;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
            if let Some(source) = self.rooms[i].source {
                self.core.pause_subscription_renewals(source)?;
            }
            if let Some(leave) = self.rooms[i].close_after {
                if self
                    .leases
                    .iter()
                    .any(|l| l.operation == leave && matches!(l.exposure, Exposure::Written { .. }))
                {
                    self.start_close_after_write(leave)?;
                }
            } else if self.rooms[i].closing_span.is_none() {
                self.initialize_room(i, now)?;
                if self.rooms[i].join.is_none()
                    && self.changing.is_none()
                    && self.free_jobs() > 0
                    && self.rooms[i].auto_epoch
                    && let (Some(member), Some(source), Some(epoch)) = (
                        self.rooms[i].member,
                        self.rooms[i].source,
                        self.rooms[i].epoch,
                    )
                {
                    let span = Span::new(now, self.limits.operation_lifetime)?;
                    match self.core.drive_epoch(
                        source,
                        member,
                        &mut self.entropy,
                        now,
                        span.logical,
                    ) {
                        Ok(Some(operation)) => self.record_job(
                            self.rooms[i].room,
                            source,
                            epoch,
                            operation,
                            span,
                            Intent::Epoch,
                        )?,
                        Ok(None)
                        | Err(domain::Error::Protocol(Fault::NotReady | Fault::WouldBlock)) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            if self.core.has_work(self.rooms[i].room)? {
                self.scan_remaining = self.rooms.len();
            }
            self.take_domain_work(self.rooms[i].room)?;
            if self
                .core
                .operations(self.rooms[i].room)?
                .any(|(_, p)| p == OperationPhase::Prepared)
            {
                self.scan_remaining = self.rooms.len();
            }
            self.execute_work(now)?;
            self.decrypt_some()?;
            self.observe_rooms()?;
        }
        self.observe_subscriptions(Some(now))
            .map_err(|(_, error)| Error::Domain(error))?;
        self.drive_subscriptions(now)?;
        self.execute_work(now)?;
        self.decrypt_some()?;
        Ok(())
    }
    pub(crate) fn local_runnable(&self) -> Result<bool, Error> {
        Ok((!self.domain_blocked
            && (self.scan_remaining > 0
                || self.subscription_scan_remaining > 0 && self.free_jobs() > 0))
            || self.decrypt_remaining > 0
            || self.work_index().is_some())
    }
}
