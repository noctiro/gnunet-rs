//! Callable actual room/message/history/subscription operations. Admission
//! prepares finite original work; later native/provider observations do the rest.
use crate::{types::*, *};
use domain::{OperationPhase, RoomPhase, SourceRole};
use gnunet_types::Error as Fault;
use std::time::Duration;
use wire::{
    body::{Body, Text},
    envelope::Kind,
};
fn public_message(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::NAME
            | Kind::INVITE
            | Kind::TEXT
            | Kind::FILE
            | Kind::TICKET
            | Kind::TAG
            | Kind::SUBSCRIPTION
            | Kind::TALK
    )
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    fn room_source(
        &mut self,
        key: Hash,
    ) -> Result<(usize, Room<'a>, Source<'a>, native::Epoch<'a>), Error> {
        self.room_source_as(key, self.selected)
    }
    pub(crate) fn room_source_as(
        &mut self,
        key: Hash,
        identity: Identity,
    ) -> Result<(usize, Room<'a>, Source<'a>, native::Epoch<'a>), Error> {
        if !self.ready() || self.changing.is_some() {
            return Err(Fault::NotReady.into());
        }
        let epoch = self.epoch.ok_or(Fault::NotReady)?;
        let public = self.signers[self.signer(identity)?].public;
        let existing = self.rooms.iter().position(|r| r.key == key);
        let (index, room) = if let Some(i) = existing {
            let r = &self.rooms[i];
            if let Some(source) = r.source {
                if r.closing_span.is_some() {
                    return Err(Fault::NotReady.into());
                }
                if r.epoch != Some(epoch) {
                    return Err(Fault::StaleGeneration.into());
                }
                return Ok((i, r.room, source, epoch));
            }
            (i, r.room)
        } else {
            if self.rooms.len() == self.limits.core.rooms {
                return Err(Fault::Capacity.into());
            }
            let profile = self.profiles.room_profile(&key).ok_or(Fault::Unavailable)?;
            let room = self.core.room_profiled(key, Some(public), profile)?;
            let i = self.rooms.len();
            self.rooms.push(LiveRoom {
                room,
                key,
                source: None,
                epoch: None,
                signer: identity,
                join: None,
                auto_epoch: self.limits.automatic_epochs,
                close_after: None,
                close_child: None,
                closing_span: None,
                member: None,
                recipient_public: None,
                pending_identity: None,
                replacement_key: None,
                identity_operation: None,
            });
            (i, room)
        };
        self.core.configure_reopen(room, public)?;
        let source = self.core.attach_source(
            room,
            SourceRole::Client,
            wire::padding::Decode::Absent,
            Some(public),
        )?;
        self.core.create_submitted(source)?;
        let r = &mut self.rooms[index];
        r.source = Some(source);
        r.epoch = Some(epoch);
        r.signer = identity;
        r.close_after = None;
        r.join = None;
        Ok((index, room, source, epoch))
    }
    /// Actually prepare official OPEN on the current CREATE-written original
    /// MQ. A prior closed room retains history while obtaining a new room lease.
    pub fn open_room(
        &mut self,
        key: Hash,
        timeout: Duration,
    ) -> Result<(Room<'a>, Operation<'a>), Error> {
        let deadline = self.deadline(timeout)?;
        self.open_room_bounded(key, deadline)
    }
    /// Actual OPEN using the original immutable caller budget, including retries.
    pub fn open_room_bounded(
        &mut self,
        key: Hash,
        deadline: Deadline,
    ) -> Result<(Room<'a>, Operation<'a>), Error> {
        let (_, span) = self.admission_bounded(deadline)?;
        self.membership_capacity(&key, None)?;
        let (_, room, source, epoch) = self.room_source(key)?;
        let operation = self.core.open(source, span.logical)?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        self.remember_membership(room, None, span, operation);
        Ok((room, operation))
    }
    /// Actually prepare official ENTRY through the supplied original peer door.
    pub fn enter_room(
        &mut self,
        key: Hash,
        door: [u8; 32],
        timeout: Duration,
    ) -> Result<(Room<'a>, Operation<'a>), Error> {
        let deadline = self.deadline(timeout)?;
        self.enter_room_bounded(key, door, deadline)
    }
    /// Actual ENTRY keeping the same door and immutable caller budget.
    pub fn enter_room_bounded(
        &mut self,
        key: Hash,
        door: [u8; 32],
        deadline: Deadline,
    ) -> Result<(Room<'a>, Operation<'a>), Error> {
        let (_, span) = self.admission_bounded(deadline)?;
        self.membership_capacity(&key, Some(door))?;
        let (_, room, source, epoch) = self.room_source(key)?;
        let operation = self.core.enter(source, door, span.logical)?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        self.remember_membership(room, Some(door), span, operation);
        Ok((room, operation))
    }
    /// Real SYNC, with the original native bound and room cursor preserved.
    pub fn synchronize(
        &mut self,
        room: Room<'a>,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let (_, span) = self.admission(timeout)?;
        let (_, source, epoch) = self.live_source(room)?;
        let operation = self.core.synchronize(source, span.logical)?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    pub(crate) fn member(&self, room: Room<'a>) -> Result<MemberSession<'a>, Error> {
        Ok(self.core.local_member(room)?.ok_or(Fault::NotReady)?)
    }
    pub(crate) fn sending(
        &self,
        room: Room<'a>,
    ) -> Result<(usize, Source<'a>, native::Epoch<'a>, MemberSession<'a>), Error> {
        let (i, source, epoch) = self.live_source(room)?;
        if self.changing.is_some()
            || self.rooms[i].closing_span.is_some()
            || self.rooms[i].close_after.is_some()
            || self.rooms[i].join.is_some()
            || !matches!(self.core.phase(room)?, RoomPhase::Open | RoomPhase::Entered)
        {
            return Err(Fault::NotReady.into());
        }
        Ok((i, source, epoch, self.member(room)?))
    }
    /// Queue one actual typed public member message. Service/peer implicit
    /// kinds and raw encryption wrappers cannot bypass the real domain checks.
    pub fn send(
        &mut self,
        room: Room<'a>,
        body: Body<'_>,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let deadline = self.deadline(timeout)?;
        self.send_bounded(room, body, deadline)
    }
    /// Queue one actual member message without renewing a blocked intent.
    pub fn send_bounded(
        &mut self,
        room: Room<'a>,
        body: Body<'_>,
        deadline: Deadline,
    ) -> Result<Operation<'a>, Error> {
        if !public_message(body.kind()) {
            return Err(Fault::PermissionDenied.into());
        }
        let (now, span) = self.admission_bounded(deadline)?;
        let (_, source, epoch, member) = self.sending(room)?;
        self.subscription_capacity(room, body)?;
        let operation = if crypto::message::permits_private(body.kind()) {
            let (encrypted, rest) = self.buffers.split_first_mut().ok_or(Fault::Conflict)?;
            let scratch = rest.first_mut().ok_or(Fault::Conflict)?;
            match self.core.prepare_secret(
                source,
                member,
                body,
                encrypted,
                scratch,
                &mut self.entropy,
                now,
                span.logical,
            ) {
                Ok(op) => op,
                Err(domain::Error::Protocol(Fault::NotReady)) if self.core.room_flags(room)?.0 => {
                    self.core
                        .prepare_send(source, member, body, now, span.logical)?
                }
                Err(e) => return Err(e.into()),
            }
        } else {
            self.core
                .prepare_send(source, member, body, now, span.logical)?
        };
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        self.remember_subscription(room, body, source, member, operation, span);
        self.core.pause_subscription_renewals(source)?;
        if span.expired(None) {
            self.capture_stop(StopCause::Deadline(operation), false, None);
            return Err(Fault::Timeout.into());
        }
        Ok(operation)
    }
    /// Canonical official TEXT, without a guessed NUL terminator or private type.
    pub fn send_text(
        &mut self,
        room: Room<'a>,
        text: &[u8],
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        self.send(
            room,
            Body::Text {
                text: Text::new(text)?,
            },
            timeout,
        )
    }
    /// Canonical TEXT preserving the caller's fixed logical/native budget.
    pub fn send_text_bounded(
        &mut self,
        room: Room<'a>,
        text: &[u8],
        deadline: Deadline,
    ) -> Result<Operation<'a>, Error> {
        self.send_bounded(
            room,
            Body::Text {
                text: Text::new(text)?,
            },
            deadline,
        )
    }
    /// Actual private HPKE send preserving one original recipient intent budget.
    pub fn send_private_bounded(
        &mut self,
        room: Room<'a>,
        recipient: MemberSession<'a>,
        body: Body<'_>,
        deadline: Deadline,
    ) -> Result<Operation<'a>, Error> {
        Ok(self
            .send_private_profiled_bounded(
                room,
                recipient,
                body,
                ShortLayout::same(self.core.local_profile()),
                deadline,
            )?
            .message())
    }
    /// Real HPKE private send to an actual advertised member session. Scratch
    /// and entropy belong to this bounded owner; no recipient key is invented.
    pub fn send_private(
        &mut self,
        room: Room<'a>,
        recipient: MemberSession<'a>,
        body: Body<'_>,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        Ok(self
            .send_private_with_transcript(room, recipient, body, timeout)?
            .message())
    }
    /// Actual recipient HPKE send plus a separate HPKE sender transcript when
    /// recipient differs from self. Each has its original distinct operation;
    /// creating the transcript never fabricates message delivery or an ACK.
    pub fn send_private_with_transcript(
        &mut self,
        room: Room<'a>,
        recipient: MemberSession<'a>,
        body: Body<'_>,
        timeout: Duration,
    ) -> Result<PrivateSend<'a>, Error> {
        self.send_private_profiled(
            room,
            recipient,
            body,
            ShortLayout::same(self.core.local_profile()),
            timeout,
        )
    }
    /// Actually encode and HPKE-encrypt the recipient's explicit short grammar.
    /// The outer signature remains in this client's selected producer layout.
    /// A separate sender transcript retains the recipient plaintext body width
    /// without rewriting its original encrypted or signed message bytes.
    pub fn send_private_profiled(
        &mut self,
        room: Room<'a>,
        recipient: MemberSession<'a>,
        body: Body<'_>,
        payload: ShortLayout,
        timeout: Duration,
    ) -> Result<PrivateSend<'a>, Error> {
        let deadline = self.deadline(timeout)?;
        self.send_private_profiled_bounded(room, recipient, body, payload, deadline)
    }
    /// Actual private send/transcript with explicit grammar and unchanged budget.
    pub fn send_private_profiled_bounded(
        &mut self,
        room: Room<'a>,
        recipient: MemberSession<'a>,
        body: Body<'_>,
        payload: ShortLayout,
        deadline: Deadline,
    ) -> Result<PrivateSend<'a>, Error> {
        payload.validate()?;
        if !public_message(body.kind()) || !crypto::message::permits_private(body.kind()) {
            return Err(Fault::PermissionDenied.into());
        }
        let (now, span) = self.admission_bounded(deadline)?;
        let (_, source, epoch, member) = self.sending(room)?;
        let transcript = recipient != member;
        let needed = if transcript { 2 } else { 1 };
        if self.free_jobs() < needed
            || self
                .core
                .operations(room)?
                .count()
                .checked_add(needed)
                .is_none_or(|n| n > self.limits.core.operations_per_room)
        {
            return Err(Fault::WouldBlock.into());
        }
        self.next_job
            .checked_add(needed as u64)
            .ok_or(Fault::Overflow)?;
        let (encrypted, rest) = self.buffers.split_first_mut().ok_or(Fault::Conflict)?;
        let scratch = rest.first_mut().ok_or(Fault::Conflict)?;
        let message = self.core.prepare_private_profiled(
            source,
            member,
            recipient,
            body,
            payload,
            encrypted,
            scratch,
            &mut self.entropy,
            now,
            span.logical,
        )?;
        self.record_job(room, source, epoch, message, span, Intent::User)?;
        let original_layout = domain::ClientLayout {
            original: domain::OriginalLayout::same(self.core.local_profile()),
            plaintext: payload,
            transcript: payload,
            identifier_order: None,
        };
        self.leases
            .iter_mut()
            .find(|l| l.operation == message)
            .ok_or(Fault::StaleGeneration)?
            .layout = Some(original_layout);
        if span.expired(None) {
            self.capture_stop(StopCause::Deadline(message), false, None);
            return Err(Fault::Timeout.into());
        }
        if !transcript {
            return Ok(PrivateSend {
                message,
                transcript: None,
            });
        }
        let result = (|| -> Result<Operation<'a>, Error> {
            let original = self
                .core
                .operations(room)?
                .find_map(|(b, _)| (b.operation() == message).then_some(*b.message()))
                .ok_or(Fault::StaleGeneration)?;
            let recipient_public = *self.core.member_public(recipient)?;
            let buffer = self.buffers.first_mut().ok_or(Fault::Conflict)?;
            buffer.encode_transcript(
                &original,
                wire::PublicKey::new(&recipient_public)?,
                body,
                payload.body,
            )?;
            let owned = domain::OwnedBytes::copy_from(buffer.expose());
            buffer.clear();
            let owned = owned?;
            let typed = Body::decode(Kind::TRANSCRIPT, owned.expose(), self.core.local_profile())?;
            let (encrypted, rest) = self.buffers.split_first_mut().ok_or(Fault::Conflict)?;
            let scratch = rest.first_mut().ok_or(Fault::Conflict)?;
            let operation = self.core.prepare_private(
                source,
                member,
                member,
                typed,
                encrypted,
                scratch,
                &mut self.entropy,
                now,
                span.logical,
            )?;
            self.record_job(room, source, epoch, operation, span, Intent::Transcript)?;
            self.leases
                .iter_mut()
                .find(|l| l.operation == operation)
                .ok_or(Fault::StaleGeneration)?
                .layout = Some(domain::ClientLayout {
                original: domain::OriginalLayout::same(self.core.local_profile()),
                plaintext: ShortLayout::same(self.core.local_profile()),
                transcript: ShortLayout::same(payload.body),
                identifier_order: None,
            });
            Ok(operation)
        })();
        let transcript = match result {
            Ok(op) => op,
            Err(error) => {
                self.capture_error(error);
                return Err(Fault::Closed.into());
            }
        };
        if span.expired(None) {
            self.capture_stop(StopCause::Deadline(transcript), false, None);
            return Err(Fault::Timeout.into());
        }
        Ok(PrivateSend {
            message,
            transcript: Some(transcript),
        })
    }
    /// Real shared-epoch AEAD send under an actually admitted current key.
    pub fn send_secret(
        &mut self,
        room: Room<'a>,
        body: Body<'_>,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        self.send_secret_profiled(
            room,
            body,
            ShortLayout::same(self.core.local_profile()),
            timeout,
        )
    }
    /// Actual encrypted epoch broadcast with an explicit shared plaintext
    /// decoder contract. One ciphertext has one immutable short layout; no
    /// private per-recipient wire tag or duplicate logical message is invented.
    pub fn send_secret_profiled(
        &mut self,
        room: Room<'a>,
        body: Body<'_>,
        payload: ShortLayout,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        payload.validate()?;
        if !public_message(body.kind()) || !crypto::message::permits_private(body.kind()) {
            return Err(Fault::PermissionDenied.into());
        }
        let (now, span) = self.admission(timeout)?;
        let (_, source, epoch, member) = self.sending(room)?;
        let (encrypted, rest) = self.buffers.split_first_mut().ok_or(Fault::Conflict)?;
        let scratch = rest.first_mut().ok_or(Fault::Conflict)?;
        let operation = self.core.prepare_secret_profiled(
            source,
            member,
            body,
            payload,
            encrypted,
            scratch,
            &mut self.entropy,
            now,
            span.logical,
        )?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        self.leases
            .iter_mut()
            .find(|l| l.operation == operation)
            .ok_or(Fault::StaleGeneration)?
            .layout = Some(domain::ClientLayout {
            original: domain::OriginalLayout::same(self.core.local_profile()),
            plaintext: payload,
            transcript: payload,
            identifier_order: None,
        });
        if span.expired(None) {
            self.capture_stop(StopCause::Deadline(operation), false, None);
            return Err(Fault::Timeout.into());
        }
        Ok(operation)
    }
    /// Real member-owned NAME update.
    pub fn set_name(
        &mut self,
        room: Room<'a>,
        name: &[u8],
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        self.send(
            room,
            Body::Name {
                name: Text::new(name)?,
            },
            timeout,
        )
    }
    /// Queue the actual signed subscription interval. Renewal is applied only
    /// by a real echoed subscription; KEEP_ALIVE creates no fabricated ACK.
    pub fn subscribe(
        &mut self,
        room: Room<'a>,
        discourse: ShortHash,
        duration: Duration,
        keep_alive: bool,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let micros = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
        self.send(
            room,
            Body::Subscription {
                discourse: &discourse,
                time: gnunet_wire::official::RelativeTime::from_micros(micros),
                flags: if keep_alive { 2 } else { 0 },
            },
            timeout,
        )
    }
    /// Actual signed subscription without renewing a blocked caller budget.
    pub fn subscribe_bounded(
        &mut self,
        room: Room<'a>,
        discourse: ShortHash,
        duration: Duration,
        keep_alive: bool,
        deadline: Deadline,
    ) -> Result<Operation<'a>, Error> {
        let micros = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
        self.send_bounded(
            room,
            Body::Subscription {
                discourse: &discourse,
                time: gnunet_wire::official::RelativeTime::from_micros(micros),
                flags: if keep_alive { 2 } else { 0 },
            },
            deadline,
        )
    }
    /// Actual unsubscribe flag1 with zero interval, not a nonexistent IPC cancel.
    pub fn unsubscribe(
        &mut self,
        room: Room<'a>,
        discourse: ShortHash,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        self.send(
            room,
            Body::Subscription {
                discourse: &discourse,
                time: gnunet_wire::official::RelativeTime::ZERO,
                flags: 1,
            },
            timeout,
        )
    }
    /// Actual signed deletion, restricted by original session ownership.
    pub fn delete_message(
        &mut self,
        room: Room<'a>,
        hash: Hash,
        delay: Duration,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let micros = u64::try_from(delay.as_micros()).map_err(|_| Fault::Overflow)?;
        let (now, span) = self.admission(timeout)?;
        let (_, source, epoch, member) = self.sending(room)?;
        let operation = self.core.prepare_send(
            source,
            member,
            Body::Deletion {
                hash: &hash,
                delay: gnunet_wire::official::RelativeTime::from_micros(micros),
            },
            now,
            span.logical,
        )?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    /// Request the real original hash; an eventual Missing remains an actual
    /// absence observation, never an arbitrary matching SEND completion.
    pub fn request_message(
        &mut self,
        room: Room<'a>,
        hash: Hash,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let deadline = self.deadline(timeout)?;
        self.request_message_bounded(room, hash, deadline)
    }
    /// Real GET under the unchanged original history request budget.
    pub fn request_message_bounded(
        &mut self,
        room: Room<'a>,
        hash: Hash,
        deadline: Deadline,
    ) -> Result<Operation<'a>, Error> {
        let (now, span) = self.admission_bounded(deadline)?;
        let (_, source, epoch) = self.live_source(room)?;
        let operation = self.core.request_missing(source, hash, now, span.logical)?;
        self.record_job(room, source, epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    /// Borrow actual cached content/tombstone. This schedules no retrieval.
    pub fn message(&self, room: Room<'a>, hash: &Hash) -> Result<MessageRef<'_, 'a>, Error> {
        Ok(self.core.message(room, hash)?)
    }
    /// Actual completed private recipient, resolved from the successful key's
    /// original association or accepted own target intent. Missing historical
    /// member evidence remains None rather than using the selected identity.
    pub fn recipient(
        &self,
        room: Room<'a>,
        hash: &Hash,
    ) -> Result<Option<domain::Contact<'a>>, Error> {
        Ok(self.core.recipient(room, hash)?)
    }
    /// Borrow actual member-authorized cached history. Use History::try_next;
    /// missing original data can be requested explicitly with request_message.
    pub fn history<'s, 'w>(
        &'s self,
        member: MemberSession<'a>,
        hash: &Hash,
        workspace: &'w mut HistoryWorkspace,
    ) -> Result<History<'s, 'w, 'a>, Error> {
        Ok(self.core.history(member, hash, workspace)?)
    }
    /// Prepare the actual LEAVE whole-write then CLOSE sequence. Room-specific
    /// earlier jobs must first settle, so the real CLOSE response can retire its
    /// lease without adopting or discarding old outstanding request debt.
    pub fn close_room(&mut self, room: Room<'a>, timeout: Duration) -> Result<Closing<'a>, Error> {
        let deadline = self.deadline(timeout)?;
        self.close_room_bounded(room, deadline)
    }
    /// Refuse new automatic/user work for this original room under its fixed
    /// close intent. Existing native/provider work remains driven. This creates
    /// no LEAVE, CLOSE operation, successful write or room-retirement proof.
    pub fn quiesce_room_bounded(
        &mut self,
        room: Room<'a>,
        deadline: Deadline,
    ) -> Result<(), Error> {
        if deadline.owner != self.owner {
            return Err(Fault::StaleGeneration.into());
        }
        if deadline.expired(None) {
            return Err(Fault::Timeout.into());
        }
        let (index, _, _) = self.live_source(room)?;
        let now = self.sample()?;
        if deadline.expired(Some(now)) {
            return Err(Fault::Timeout.into());
        }
        if let Some(original) = self.rooms[index].closing_span {
            if original.logical != deadline.span.logical || original.hard != deadline.span.hard {
                return Err(Fault::Conflict.into());
            }
        } else {
            self.rooms[index].closing_span = Some(deadline.span);
            self.wake_domain();
        }
        self.memberships.retain(|m| m.room != room);
        self.subscriptions.retain(|s| s.room != room);
        Ok(())
    }
    /// Original LEAVE/CLOSE sequence under a single unchanged cleanup budget.
    pub fn close_room_bounded(
        &mut self,
        room: Room<'a>,
        deadline: Deadline,
    ) -> Result<Closing<'a>, Error> {
        self.quiesce_room_bounded(room, deadline)?;
        let (now, span) = self.admission_bounded(deadline)?;
        if self
            .leases
            .len()
            .checked_add(self.reservations)
            .and_then(|n| n.checked_add(2))
            .is_none_or(|n| n > self.limits.operations)
        {
            return Err(Fault::WouldBlock.into());
        }
        let (i, source, epoch) = self.live_source(room)?;
        let member = self.member(room)?;
        if self.rooms[i].close_after.is_some()
            || self.rooms[i].join.is_some()
            || !matches!(self.core.phase(room)?, RoomPhase::Open | RoomPhase::Entered)
        {
            return Err(Fault::NotReady.into());
        }
        if self.leases.iter().any(|l| {
            l.room == room
                && self.core.operation_phase(l.operation).is_ok_and(|p| {
                    !matches!(
                        p,
                        OperationPhase::Complete
                            | OperationPhase::Failed
                            | OperationPhase::Cancelled
                    )
                })
        }) {
            return Err(Fault::WouldBlock.into());
        }
        let operation = self.core.prepare_leave(source, member, now, span.logical)?;
        self.record_job(room, source, epoch, operation, span, Intent::LeaveClose)?;
        self.rooms[i].close_after = Some(operation);
        self.rooms[i].closing_span = Some(span);
        self.reservations += 1;
        Ok(Closing {
            room,
            leave: operation,
        })
    }
    /// Forget detached cached state after its actual room lease has retired.
    /// This never closes another room's shared native connection.
    pub fn forget_room(&mut self, room: Room<'a>) -> Result<(), Error> {
        let i = self.room_index(room)?;
        if self.rooms[i].source.is_some() || self.leases.iter().any(|l| l.room == room) {
            return Err(Fault::NotReady.into());
        }
        self.core.forget_room(room)?;
        self.memberships.retain(|m| m.room != room);
        self.subscriptions.retain(|s| s.room != room);
        self.rooms.remove(i);
        self.wake_domain();
        Ok(())
    }
    /// Explicitly select an imported handle identity while no live room lease
    /// exists. Active identity changes require real signed KEY transitions.
    pub fn select_identity(&mut self, identity: Identity) -> Result<(), Error> {
        self.signer(identity)?;
        if self.rooms.iter().any(|r| r.source.is_some())
            || !self.leases.is_empty()
            || self.changing.is_some()
        {
            return Err(Fault::NotReady.into());
        }
        self.selected = identity;
        Ok(())
    }
    /// Change the single handle identity through real KEY messages in every
    /// active room. The output contains original jobs, never synthetic ACKs.
    /// No room may have unsettled local work; the old keys remain available for
    /// original drafts and retained historical sessions until explicitly retired.
    pub fn change_identity(
        &mut self,
        identity: Identity,
        timeout: Duration,
        operations: &mut [Option<Operation<'a>>],
    ) -> Result<usize, Error> {
        let selected = self.signer(identity)?;
        let public = self.signers[selected].public;
        let (now, span) = self.admission(timeout)?;
        if self.changing.is_some() {
            return Err(Fault::NotReady.into());
        }
        if identity == self.selected {
            return Ok(0);
        }
        let count = self.rooms.iter().filter(|r| r.source.is_some()).count();
        if count > operations.len() || count > self.free_jobs() {
            return Err(Fault::Capacity.into());
        }
        self.next_job
            .checked_add(u64::try_from(count).map_err(|_| Fault::Overflow)?)
            .ok_or(Fault::Overflow)?;
        for r in &self.rooms {
            if r.source.is_none() {
                continue;
            }
            self.sending(r.room)?;
            if self.leases.iter().any(|l| {
                l.room == r.room
                    && self.core.operation_phase(l.operation).is_ok_and(|p| {
                        !matches!(
                            p,
                            OperationPhase::Complete
                                | OperationPhase::Failed
                                | OperationPhase::Cancelled
                        )
                    })
            }) {
                return Err(Fault::WouldBlock.into());
            }
        }
        // All entropy is drawn before the first protocol mutation. The slots
        // already belong to bounded room metadata, not an uncharged staging Vec.
        for i in 0..self.rooms.len() {
            if self.rooms[i].source.is_none() {
                continue;
            }
            match crypto::EcdheSecret::generate_hpke(&mut self.entropy) {
                Ok(key) => self.rooms[i].replacement_key = Some(key),
                Err(error) => {
                    for r in &mut self.rooms {
                        r.replacement_key = None;
                    }
                    return Err(error.into());
                }
            }
            if span.expired(None) {
                for r in &mut self.rooms {
                    r.replacement_key = None;
                }
                return Err(Fault::Timeout.into());
            }
        }
        self.changing = Some(identity);
        let mut admitted = 0;
        for i in 0..self.rooms.len() {
            let Some(source) = self.rooms[i].source else {
                continue;
            };
            let result = (|| {
                let room = self.rooms[i].room;
                let epoch = self.rooms[i].epoch.ok_or(Fault::StaleGeneration)?;
                let member = self.member(room)?;
                let mut hpke = [0; 36];
                self.rooms[i]
                    .replacement_key
                    .as_ref()
                    .ok_or(Fault::Conflict)?
                    .public_key()
                    .encode_hpke(&mut hpke)?;
                let op = self.core.prepare_send(
                    source,
                    member,
                    Body::Key {
                        public_key: wire::PublicKey::new(&public)?,
                        hpke_key: wire::keys::HpkePublicKey::new(&hpke)?,
                    },
                    now,
                    span.logical,
                )?;
                self.record_job(room, source, epoch, op, span, Intent::User)?;
                self.rooms[i].pending_identity = Some(identity);
                self.rooms[i].identity_operation = Some(op);
                Ok::<_, Error>(op)
            })();
            match result {
                Ok(operation) => {
                    operations[admitted] = Some(operation);
                    admitted += 1;
                }
                Err(error) => {
                    // Partial multi-room admission is an actual exposed intent;
                    // physical close preserves every original job and error.
                    self.capture_error(error);
                    return Err(Fault::Closed.into());
                }
            }
        }
        if admitted == 0 {
            self.selected = identity;
            self.changing = None;
        }
        if span.expired(None) {
            self.capture_stop(StopCause::Initialization, false, None);
            return Err(Fault::Timeout.into());
        }
        self.wake_domain();
        Ok(admitted)
    }
    /// Enable/disable automatic real epoch work for this original room.
    pub fn automatic_epochs(&mut self, room: Room<'a>, enabled: bool) -> Result<(), Error> {
        let i = self.room_index(room)?;
        self.rooms[i].auto_epoch = enabled;
        self.wake_domain();
        Ok(())
    }
}
