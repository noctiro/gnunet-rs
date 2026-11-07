//! Completed outer envelopes are quarantined as actual DV input, never CORE.
use super::*;
/// One complete original communicator DV input with its captured source and
/// first-byte bounds. Neither the bytes nor this envelope assert authenticity.
pub struct NativeInput<'a> {
    /// Exact accepting local DV source captured for the original physical input.
    pub source: &'a Source,
    /// Original communicator MQ owner; never a replacement connection.
    pub owner: &'a ClientId,
    /// Complete official communicator Incoming frame, carrying1218/1219.
    pub bytes: &'a [u8],
    /// Original native first-byte bound projected into the Engine mono epoch.
    pub until: MonoInstant,
    /// Original canonical first-byte target, never recreated after staging.
    pub absolute_until: AbsoluteTime,
}
/// Actual complete original reassembly/reliable input awaiting Actor capacity.
pub struct InboxPacket<'a> {
    /// Current original local admission identity; not a wire RID/proof.
    pub id: IngressId,
    /// Actual original direct queue, including its route generation.
    pub queue: &'a DirectQueue,
    /// Immutable complete official1218/1219 frame, not authenticated plaintext.
    pub bytes: &'a [u8],
    /// Original reassembly/receive scheduling bound, never renewed on retry.
    pub until: MonoInstant,
    /// Captured canonical target for a native raw envelope. Outer reassembly
    /// retains its existing scheduling-only policy and supplies None.
    pub absolute_until: Option<AbsoluteTime>,
}
pub(in crate::engine) struct HeldSource {
    pub(in crate::engine) source: Source,
    pub(in crate::engine) until: u64,
    pub(in crate::engine) absolute_until: Option<AbsoluteTime>,
}
struct Inbox {
    id: IngressId,
    origin: Option<Ingress>,
    queue: DirectQueue,
    body: Zeroizing<Vec<u8>>,
    until: u64,
    absolute_until: Option<AbsoluteTime>,
}
pub(super) struct RxBook {
    inbox: VecDeque<Inbox>,
}
impl RxBook {
    pub(super) fn new(limits: Limits) -> Result<Self, Error> {
        let mut inbox = VecDeque::new();
        inbox
            .try_reserve_exact(limits.messages)
            .map_err(|_| Error::Capacity)?;
        Ok(Self { inbox })
    }
}
impl Engine {
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the same owned frame/source/deadlines/FC without allocating a second owner"
    )]
    pub(in crate::engine) fn dv_stage_inbox(&mut self, held: Held) -> Result<(), Rejected<Held>> {
        let checked = (|| {
            let d = held.dv.as_ref().ok_or(Error::Malformed)?;
            self.dv_check_source(&d.source)?;
            if self.last_monotonic >= d.until {
                return Err(Error::Deadline);
            }
            if self.dv_bridge.ingresses.len() == self.limits.messages
                || self.dv_bridge.rx.inbox.len() == self.limits.messages
            {
                return Err(Error::WouldBlock);
            }
            if self
                .buffered
                .checked_add(held.message.len())
                .is_none_or(|n| n > self.limits.bytes)
            {
                return Err(Error::WouldBlock);
            }
            let route = self
                .routes
                .iter()
                .find(|r| {
                    r.owner == held.owner
                        && r.description.peer == held.peer
                        && r.valid_until > self.last_monotonic
                })
                .ok_or(Error::NotReady)?;
            let queue = DirectQueue {
                owner: route.owner.clone(),
                peer: held.peer,
                queue: route.description.id,
                route: route.serial,
            };
            let serial = self.dv_bridge.next()?;
            Ok((queue, serial))
        })();
        let (queue, serial) = match checked {
            Ok(v) => v,
            Err(reason) => {
                return Err(Rejected {
                    reason,
                    value: held,
                });
            }
        };
        let Held {
            owner,
            peer,
            message,
            token,
            dv,
        } = held;
        let HeldSource {
            source,
            until,
            absolute_until,
        } = match dv {
            Some(d) => d,
            None => {
                return Err(Rejected {
                    reason: Error::Malformed,
                    value: Held {
                        owner,
                        peer,
                        message,
                        token,
                        dv: None,
                    },
                });
            }
        };
        let id = IngressId {
            source: source.clone(),
            serial,
        };
        self.dv_bridge.ingresses.push(IngressRow {
            source: source.clone(),
            serial,
            owner,
            carrier: peer,
            flow: token,
            admitted: false,
            delivered: false,
            failure: None,
            pending: None,
        });
        self.buffered += message.len();
        self.dv_bridge.rx.inbox.push_back(Inbox {
            id,
            origin: Some(Ingress { source, serial }),
            queue,
            body: message,
            until,
            absolute_until,
        });
        Ok(())
    }
    /// Actual retained original envelope, no payload copy or crypto assertion.
    pub fn dv_inbox(&self) -> Option<InboxPacket<'_>> {
        self.dv_bridge
            .rx
            .inbox
            .iter()
            .find(|r| r.origin.is_some())
            .map(|r| InboxPacket {
                id: r.id.clone(),
                queue: &r.queue,
                bytes: &r.body,
                until: MonoInstant(r.until),
                absolute_until: r.absolute_until,
            })
    }
    /// Reserve original J for a synchronous actual Actor admission call.
    pub fn dv_claim_inbox(&mut self, id: &IngressId) -> Result<Ingress, Error> {
        self.dv_check_source(id.source())?;
        self.dv_bridge
            .rx
            .inbox
            .iter_mut()
            .find(|r| r.id.source == id.source && r.id.serial == id.serial)
            .and_then(|r| r.origin.take())
            .ok_or(Error::Stale)
    }
    /// Read original bytes while the same actual admission holds its J.
    pub fn dv_inbox_get(&self, id: &IngressId) -> Result<InboxPacket<'_>, Error> {
        let r = self
            .dv_bridge
            .rx
            .inbox
            .iter()
            .find(|r| r.id.source == id.source && r.id.serial == id.serial)
            .ok_or(Error::Stale)?;
        Ok(InboxPacket {
            id: r.id.clone(),
            queue: &r.queue,
            bytes: &r.body,
            until: MonoInstant(r.until),
            absolute_until: r.absolute_until,
        })
    }
    /// Actual Actor copied/admitted this envelope. Only then drop the Engine's
    /// former staging body; its original FC row remains until actual Finished.
    pub fn dv_inbox_admitted(&mut self, id: &IngressId) -> Result<(), Error> {
        let i = self
            .dv_bridge
            .rx
            .inbox
            .iter()
            .position(|r| {
                r.id.source == id.source && r.id.serial == id.serial && r.origin.is_none()
            })
            .ok_or(Error::Stale)?;
        self.dv_input_admitted(id)?;
        let r = self.dv_bridge.rx.inbox.remove(i).ok_or(Error::Stale)?;
        self.buffered -= r.body.len();
        Ok(())
    }
    /// Zero actual admission. Replace only its local reservation brand, keeping
    /// the SAME physical FC/source/body and original bound; old refused J cannot
    /// later complete a newer admission of this same immutable envelope.
    pub fn dv_reset_inbox(&mut self, id: &IngressId) -> Result<IngressId, Error> {
        let i = self.dv_ingress_id(id)?;
        if self.dv_bridge.ingresses[i].admitted {
            return Err(Error::Conflict);
        }
        let serial = self.dv_bridge.next()?;
        let r = self
            .dv_bridge
            .rx
            .inbox
            .iter_mut()
            .find(|r| r.id.source == id.source && r.id.serial == id.serial && r.origin.is_none())
            .ok_or(Error::Stale)?;
        self.dv_bridge.ingresses[i].serial = serial;
        r.id.serial = serial;
        r.origin = Some(Ingress {
            source: id.source.clone(),
            serial,
        });
        let current = r.id.clone();
        let index = self
            .dv_bridge
            .rx
            .inbox
            .iter()
            .position(|r| r.id.source == current.source && r.id.serial == current.serial)
            .ok_or(Error::Stale)?;
        let row = self.dv_bridge.rx.inbox.remove(index).ok_or(Error::Stale)?;
        self.dv_bridge.rx.inbox.push_back(row);
        Ok(current)
    }
    /// Original unadmitted source owner, including complete envelopes waiting
    /// for a bounded inbox slot. Physical cleanup does not need any clock.
    pub fn dv_unadmitted_owner(&self, source: &Source) -> Option<ClientId> {
        self.dv_bridge
            .rx
            .inbox
            .iter()
            .find(|r| r.id.source == *source)
            .and_then(|r| {
                self.dv_bridge
                    .ingresses
                    .iter()
                    .find(|i| i.source == r.id.source && i.serial == r.id.serial)
                    .map(|i| i.owner.clone())
            })
            .or_else(|| {
                self.held
                    .iter()
                    .find(|h| h.dv.as_ref().is_some_and(|d| d.source == *source))
                    .map(|h| h.owner.clone())
            })
    }
    /// Discard only never-admitted envelopes of a retiring source. Native caller
    /// physically closes their original MQ first; no acknowledgement is forged.
    pub fn dv_discard_inbox_source(&mut self, source: &Source) -> Result<bool, Error> {
        if self.dv_bridge.source.as_ref() != Some(source) || !self.dv_bridge.retiring {
            return Err(Error::NotReady);
        }
        let Some(i) = self
            .dv_bridge
            .rx
            .inbox
            .iter()
            .position(|r| r.id.source == *source)
        else {
            return Ok(false);
        };
        let id = self.dv_bridge.rx.inbox[i].id.clone();
        let row = self.dv_ingress_id(&id)?;
        if self.dv_bridge.ingresses[row].admitted
            || self.client(&self.dv_bridge.ingresses[row].owner).is_ok()
        {
            return Err(Error::NotReady);
        }
        self.dv_finish_incoming(Ingress {
            source: id.source,
            serial: id.serial,
        })
        .map_err(|r| r.reason)?;
        let r = self.dv_bridge.rx.inbox.remove(i).ok_or(Error::Stale)?;
        self.buffered -= r.body.len();
        Ok(true)
    }
    /// First original unadmitted source deadline, in the same Engine epoch.
    pub fn dv_inbox_deadline(&self) -> Option<MonoInstant> {
        self.dv_bridge
            .rx
            .inbox
            .iter()
            .map(|r| r.until)
            .chain(
                self.held
                    .iter()
                    .filter_map(|h| h.dv.as_ref().map(|d| d.until)),
            )
            .min()
            .map(MonoInstant)
    }
}
impl Engine {
    /// Drop one complete never-admitted original envelope after permanent remote
    /// refusal or local expiry; reserve actual FC output before freeing its body.
    pub fn dv_drop_inbox(&mut self, id: &IngressId) -> Result<IngressEnd, Error> {
        let i = self
            .dv_bridge
            .rx
            .inbox
            .iter()
            .position(|r| {
                r.id.source == id.source && r.id.serial == id.serial && r.origin.is_some()
            })
            .ok_or(Error::Stale)?;
        let row = self.dv_ingress_id(id)?;
        if self.dv_bridge.ingresses[row].admitted {
            return Err(Error::Conflict);
        }
        let result = self
            .dv_finish_incoming(Ingress {
                source: id.source.clone(),
                serial: id.serial,
            })
            .map_err(|r| r.reason)?;
        let r = self.dv_bridge.rx.inbox.remove(i).ok_or(Error::Stale)?;
        self.buffered -= r.body.len();
        Ok(result)
    }
    /// Retiring-source complete envelopes that never reached an inbox slot.
    /// Native source must actually be gone; no new clock or ACK is required.
    pub fn dv_drop_retired_held(&mut self, source: &Source) -> Result<bool, Error> {
        if self.dv_bridge.source.as_ref() != Some(source) || !self.dv_bridge.retiring {
            return Err(Error::NotReady);
        }
        let n = self.held.len();
        let mut changed = false;
        for _ in 0..n {
            let Some(h) = self.held.pop_front() else {
                break;
            };
            if h.dv.as_ref().is_some_and(|d| d.source == *source) && self.client(&h.owner).is_err()
            {
                self.buffered -= h.message.len();
                changed = true;
            } else {
                self.held.push_back(h);
            }
        }
        Ok(changed)
    }
}
impl Engine {
    /// Original native epoch reached these stored mono targets. No fresh UTC or
    /// grant is synthesized. Retire one original unadmitted packet/FC record.
    pub fn dv_expire_inbox_native(
        &mut self,
        source: &Source,
        through: MonoInstant,
    ) -> Result<bool, Error> {
        if let Some(id) = self
            .dv_bridge
            .rx
            .inbox
            .iter()
            .find(|r| r.id.source == *source && r.until <= through.0 && r.origin.is_some())
            .map(|r| r.id.clone())
        {
            self.dv_drop_inbox(&id)?;
            self.dropped = self.dropped.saturating_add(1);
            return Ok(true);
        }
        let Some(i) = self.held.iter().position(|h| {
            h.dv.as_ref()
                .is_some_and(|d| d.source == *source && d.until <= through.0)
        }) else {
            return Ok(false);
        };
        let h = &self.held[i];
        if let Some(token) = h.token
            && self.client(&h.owner).is_ok()
        {
            self.ack(h.owner.clone(), h.peer, token)?;
        }
        let h = self.held.remove(i).ok_or(Error::Stale)?;
        self.buffered -= h.message.len();
        self.dropped = self.dropped.saturating_add(1);
        Ok(true)
    }
}
