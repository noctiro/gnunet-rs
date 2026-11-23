use super::{Event, OperationBinding, OperationPhase};
use crate::{
    Brand, Contact, Error, Hash, KeyPhase, MessagePhase, Room, RoomPhase, SessionPhase, ShortHash,
    Slot,
};
use gnunet_types::Error as Fault;

/// A queued event keeps the generations reported at the transition, even if
/// those slots have been retired or reused by the time it is consumed.
pub(crate) enum QueuedEvent {
    SourceAttached {
        room: Slot,
        source: Slot,
    },
    SourceLost {
        room: Slot,
        source: Slot,
    },
    RoomChanged(Slot, RoomPhase),
    MemberChanged {
        room: Slot,
        member: Slot,
        phase: SessionPhase,
    },
    ContactChanged(Slot),
    MessageChanged(Slot, Hash, MessagePhase),
    ServicePeerMiss {
        room: Slot,
        members_before: usize,
    },
    Missing(Slot, Hash),
    SubscriptionChanged(Slot, Slot, ShortHash),
    EpochChanged(Slot, Hash),
    KeyChanged(Slot, Hash, ShortHash, KeyPhase),
    OperationChanged {
        room: Slot,
        operation: Slot,
        phase: OperationPhase,
    },
    Rejected(Slot, Hash, Error),
    ProviderFailed {
        room: Slot,
        operation: Slot,
        binding: OperationBinding,
        error: Error,
    },
}

impl QueuedEvent {
    pub(crate) fn capture<'id>(event: Event<'id>, brand: Brand<'id>) -> Result<Self, Error> {
        // Check scope before discarding the brand. Do not check whether the
        // reported generation is live; source loss follows physical removal.
        let local = |valid| {
            if valid {
                Ok(())
            } else {
                Err(Fault::StaleGeneration)
            }
        };
        let room =
            |handle: Room<'id>| local(handle == brand.room_id(handle.slot)).map(|()| handle.slot);
        let contact = |handle: Contact<'id>| {
            local(handle == brand.contact_id(handle.slot)).map(|()| handle.slot)
        };
        Ok(match event {
            Event::SourceAttached(s) => {
                local(s.core == brand)?;
                Self::SourceAttached {
                    room: s.room,
                    source: s.slot,
                }
            }
            Event::SourceLost(s) => {
                local(s.core == brand)?;
                Self::SourceLost {
                    room: s.room,
                    source: s.slot,
                }
            }
            Event::RoomChanged(r, p) => Self::RoomChanged(room(r)?, p),
            Event::MemberChanged(m, phase) => {
                local(m.core == brand)?;
                Self::MemberChanged {
                    room: m.room,
                    member: m.slot,
                    phase,
                }
            }
            Event::ContactChanged(c) => Self::ContactChanged(contact(c)?),
            Event::MessageChanged(r, h, p) => Self::MessageChanged(room(r)?, h, p),
            Event::ServicePeerMiss {
                room: r,
                members_before,
            } => Self::ServicePeerMiss {
                room: room(r)?,
                members_before,
            },
            Event::Missing(r, h) => Self::Missing(room(r)?, h),
            Event::SubscriptionChanged(r, c, d) => {
                Self::SubscriptionChanged(room(r)?, contact(c)?, d)
            }
            Event::EpochChanged(r, h) => Self::EpochChanged(room(r)?, h),
            Event::KeyChanged(r, h, i, p) => Self::KeyChanged(room(r)?, h, i, p),
            Event::OperationChanged(o, phase) => {
                local(o.core == brand)?;
                Self::OperationChanged {
                    room: o.room,
                    operation: o.slot,
                    phase,
                }
            }
            Event::Rejected(r, h, e) => Self::Rejected(room(r)?, h, e),
            Event::ProviderFailed(b, error) => {
                let operation = b.operation();
                let source = b.source();
                local(
                    operation.core == brand
                        && source.core == brand
                        && source.room == operation.room
                        && b.member()
                            .is_none_or(|m| m.core == brand && m.room == operation.room),
                )?;
                Self::ProviderFailed {
                    room: operation.room,
                    operation: operation.slot,
                    binding: b.coordinates(),
                    error,
                }
            }
        })
    }

    pub(crate) fn bind<'id>(self, brand: Brand<'id>) -> Event<'id> {
        match self {
            Self::SourceAttached { room, source } => {
                Event::SourceAttached(brand.source_id(room, source))
            }
            Self::SourceLost { room, source } => Event::SourceLost(brand.source_id(room, source)),
            Self::RoomChanged(r, p) => Event::RoomChanged(brand.room_id(r), p),
            Self::MemberChanged {
                room,
                member,
                phase,
            } => Event::MemberChanged(brand.member_id(room, member), phase),
            Self::ContactChanged(c) => Event::ContactChanged(brand.contact_id(c)),
            Self::MessageChanged(r, h, p) => Event::MessageChanged(brand.room_id(r), h, p),
            Self::ServicePeerMiss {
                room,
                members_before,
            } => Event::ServicePeerMiss {
                room: brand.room_id(room),
                members_before,
            },
            Self::Missing(r, h) => Event::Missing(brand.room_id(r), h),
            Self::SubscriptionChanged(r, c, d) => {
                Event::SubscriptionChanged(brand.room_id(r), brand.contact_id(c), d)
            }
            Self::EpochChanged(r, h) => Event::EpochChanged(brand.room_id(r), h),
            Self::KeyChanged(r, h, i, p) => Event::KeyChanged(brand.room_id(r), h, i, p),
            Self::OperationChanged {
                room,
                operation,
                phase,
            } => Event::OperationChanged(brand.operation_id(room, operation), phase),
            Self::Rejected(r, h, e) => Event::Rejected(brand.room_id(r), h, e),
            Self::ProviderFailed {
                room,
                operation,
                binding,
                error,
            } => Event::ProviderFailed(binding.bind(brand, room, operation), error),
        }
    }
}
