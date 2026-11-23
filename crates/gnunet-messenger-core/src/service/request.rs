//! Live ingress authority for a signed REQUEST across working history cutover.

use super::{ServiceAttribution, history::check_archive};
use crate::{
    CommittedServiceOriginal, Core, Error, Hash, MessagePhase, MessageRef, Mode, Slot, Source,
    SourceObservation, SourceRole,
    archive::CommittedRoomHistory,
    wire::{body::Body, envelope::Kind, message::Message},
};
use gnunet_types::Error as Fault;

/// An original REQUEST accepted on a particular live IPC or peer source.
/// The owner retains this token for the lifetime of the delivery attempt.
/// It grants no access before signature verification and semantic application.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServiceRequestAuthority<'id> {
    source: Source<'id>,
    hash: Hash,
    position: Slot,
}

impl<'id> ServiceRequestAuthority<'id> {
    /// Exact source that first supplied the original.
    pub const fn source(self) -> Source<'id> {
        self.source
    }

    /// Signed request hash.
    pub const fn hash(&self) -> &Hash {
        &self.hash
    }
}

/// An applied REQUEST resolved using live ingress authority.
pub enum ServiceRequestOriginal<'a, 'id> {
    /// Original still represented in the working room.
    Resident {
        /// Working message and its original byte location.
        message: MessageRef<'a, 'id>,
        /// Exact original bytes borrowed from the working room or its checkpoint.
        bytes: &'a [u8],
        /// Verified original signing session and live ingress.
        attribution: ServiceAttribution<'id>,
    },
    /// Original moved to the matching committed history.
    Committed {
        /// Exact signed original.
        original: CommittedServiceOriginal<'a>,
        /// Verified signing session and ingress established by the token.
        attribution: ServiceAttribution<'id>,
    },
}

impl<'id> ServiceRequestOriginal<'_, 'id> {
    /// Exact signed request hash.
    pub const fn hash(&self) -> &Hash {
        match self {
            Self::Resident { message, .. } => message.hash(),
            Self::Committed { original, .. } => original.hash(),
        }
    }

    /// Verified attribution for this live request.
    pub const fn attribution(&self) -> ServiceAttribution<'id> {
        match self {
            Self::Resident { attribution, .. } | Self::Committed { attribution, .. } => {
                *attribution
            }
        }
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Capture ingress only from a first-received working REQUEST on this source.
    /// A restored or reattached row cannot mint a token.
    pub fn service_request_authority(
        &self,
        source: Source<'id>,
        hash: &Hash,
    ) -> Result<Option<ServiceRequestAuthority<'id>>, Error> {
        self.check_request_source(source)?;
        let row = self.rooms.get(source.room)?;
        let Some(at) = row.find_node(hash) else {
            return Ok(None);
        };
        let node = row.nodes.get(at)?;
        if node.kind != Kind::REQUEST
            || node.origin.live(self.instance) != Some(source)
            || !node.origin.is_first_received()
            || node.requested
            || !node.has_original()
            || matches!(node.phase, MessagePhase::Deleted | MessagePhase::Rejected)
        {
            return Ok(None);
        }
        Ok(Some(ServiceRequestAuthority {
            source,
            hash: *hash,
            position: at,
        }))
    }

    /// Check whether a retransmitted hash already has working or committed custody.
    /// Unverified input on another source cannot suppress a new admission.
    pub fn service_request_known(
        &self,
        source: Source<'id>,
        hash: &Hash,
        archive: Option<CommittedRoomHistory<'_, '_>>,
    ) -> Result<bool, Error> {
        self.check_request_source(source)?;
        let row = self.rooms.get(source.room)?;
        check_archive(row, source.room, self.local_peer, archive)?;
        if let Some(at) = row.find_node(hash) {
            let node = row.nodes.get(at)?;
            if node.auth.is_some() || node.origin.live(self.instance) == Some(source) {
                return Ok(true);
            }
        }
        Ok(match archive {
            Some(archive) => archive.detached_sequence(hash)?.is_some(),
            None => false,
        })
    }

    /// Resolve an applied REQUEST while its original source remains attached.
    pub fn service_request_original<'a>(
        &'a self,
        authority: ServiceRequestAuthority<'id>,
        archive: Option<CommittedRoomHistory<'a, '_>>,
    ) -> Result<ServiceRequestOriginal<'a, 'id>, Error> {
        self.resolve_request(authority, archive)
            .map(|(original, _)| original)
    }

    pub(super) fn resolve_request<'a>(
        &'a self,
        authority: ServiceRequestAuthority<'id>,
        archive: Option<CommittedRoomHistory<'a, '_>>,
    ) -> Result<(ServiceRequestOriginal<'a, 'id>, &'a Hash), Error> {
        let source = authority.source;
        let role = self.check_request_source(source)?;
        let row = self.rooms.get(source.room)?;
        check_archive(row, source.room, self.local_peer, archive)?;
        if let Some(at) = row.find_node(authority.hash()) {
            let node = row.nodes.get(at)?;
            if self.service_request_authority(source, authority.hash())? != Some(authority) {
                return Err(Error::Permission);
            }
            if !node.semantic_applied || !node.epoch_indexed {
                return Err(Fault::NotReady.into());
            }
            let room = self.instance.room_id(source.room);
            let message = MessageRef::new(node, row, &self.frames, self.instance)?;
            let raw = match node.archived_original() {
                Some(range) => archive.ok_or(Fault::NotReady)?.retained_original(range)?,
                None => message.original().ok_or(Fault::Conflict)?,
            };
            let target = request_target(raw, message.layout(), message.padding())?;
            let attribution = self.service_attribution(room, authority.hash())?;
            return Ok((
                ServiceRequestOriginal::Resident {
                    message,
                    bytes: raw,
                    attribution,
                },
                target,
            ));
        }

        let cold = archive
            .ok_or(Fault::NotFound)?
            .detached_local_original(authority.hash())?
            .ok_or(Fault::NotFound)?;
        if cold.original.kind() != Kind::REQUEST
            || cold.requested
            || !cold.semantic_applied
            || cold.position != authority.position
            || cold.provenance
                != (SourceObservation {
                    room: source.room,
                    source: source.slot,
                    role,
                })
        {
            return Err(Error::Permission);
        }
        let mut attribution = self.committed_attribution(source.room, row, &cold)?;
        let member = cold.auth.session.ok_or(Fault::Authentication)?;
        attribution.member = Some(self.member_id(source.room, member));
        attribution.source = Some(source);
        let original = cold.original;
        let target = request_target(original.bytes(), original.layout(), original.padding())?;
        Ok((
            ServiceRequestOriginal::Committed {
                original,
                attribution,
            },
            target,
        ))
    }

    fn check_request_source(&self, source: Source<'id>) -> Result<SourceRole, Error> {
        if self.mode != Mode::Service || self.check_source(source).is_err() {
            return Err(Error::Permission);
        }
        let role = self.rooms.get(source.room)?.sources.get(source.slot)?.role;
        if !matches!(role, SourceRole::Client | SourceRole::Peer(_)) {
            return Err(Error::Permission);
        }
        Ok(role)
    }
}

fn request_target(
    raw: &[u8],
    layout: crate::OriginalLayout,
    padding: crate::wire::padding::Decode,
) -> Result<&Hash, Error> {
    let message = Message::decode_with_profiles(
        raw,
        layout.body_profile(Kind::REQUEST)?,
        layout.padding,
        padding,
    )?;
    let Body::Request { hash } = message.body() else {
        return Err(Error::AttributionConflict);
    };
    Ok(hash)
}
