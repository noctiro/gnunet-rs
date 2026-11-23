//! Supported detached rows and their exact signing authority.

use super::super::MessageRecord;
use crate::{
    Error, Hash, MessagePhase, OriginalSigner, SourceRole,
    state::{Authentication, Node},
    wire::{KeyType, envelope::Kind},
};
use gnunet_types::Error as Fault;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DetachedKind {
    MemberData,
    MemberRequest,
    PeerControl,
}

impl DetachedKind {
    pub(crate) const fn of(kind: Kind) -> Option<Self> {
        match kind {
            Kind::TEXT | Kind::FILE => Some(Self::MemberData),
            Kind::REQUEST => Some(Self::MemberRequest),
            Kind::PEER | Kind::CONNECTION | Kind::MISS => Some(Self::PeerControl),
            _ => None,
        }
    }

    pub(crate) fn signer(self, auth: Authentication) -> Result<OriginalSigner, Error> {
        match (self, auth.peer) {
            (Self::MemberData, None) => Ok(OriginalSigner::Member(auth.public)),
            (Self::MemberRequest, None) if auth.owner.is_some() && auth.session.is_some() => {
                Ok(OriginalSigner::Member(auth.public))
            }
            (Self::PeerControl, Some(peer))
                if auth.owner.is_none()
                    && auth.session.is_none()
                    && auth.public[..4] == KeyType::Eddsa.value().to_be_bytes()
                    && auth.public[4..] == peer =>
            {
                Ok(OriginalSigner::Peer(peer))
            }
            _ => Err(Fault::Authentication.into()),
        }
    }

    pub(in crate::archive) const fn is_deletable(self) -> bool {
        matches!(self, Self::MemberData | Self::MemberRequest)
    }

    fn check_graph_shape(self, references: &[Hash; 3], frontier_applied: bool) -> bool {
        match self {
            // A REQUEST's signed target is an operation input, not an
            // ancestry edge or a contribution to the frontier.
            Self::MemberRequest => !frontier_applied && references[1..] == [[0; 64]; 2],
            _ => *references == [[0; 64]; 3],
        }
    }

    fn check_source(signer: OriginalSigner, source: SourceRole) -> Result<(), Error> {
        match (signer, source) {
            (OriginalSigner::Peer(peer), SourceRole::ServiceSigner(local)) if peer == local => {
                Ok(())
            }
            (OriginalSigner::Peer(_) | OriginalSigner::Member(_), SourceRole::Peer(_))
            | (OriginalSigner::Member(_), SourceRole::Client) => Ok(()),
            _ => Err(Fault::Authentication.into()),
        }
    }

    pub(super) fn validate_record(row: &MessageRecord<'_>) -> Result<(), Error> {
        let kind = Self::of(row.kind).ok_or(Fault::Malformed)?;
        let supported_phase = match row.phase {
            MessagePhase::Applied if kind.is_deletable() => {
                row.delete_at.is_none() || row.deleted_by.is_some()
            }
            MessagePhase::Applied => row.delete_at.is_none() && row.deleted_by.is_none(),
            MessagePhase::Deleted => kind.is_deletable(),
            _ => false,
        };
        if !supported_phase
            || row.kind != row.semantic_kind
            || !row.complete
            || !row.semantic_applied
            || row.discourse.is_some()
            || row.transcript.is_some()
            || row.private_recipient.is_some()
            || row.cipher_layout.is_some()
            || row.plain_layout.is_some()
            || row.transcript_layout.is_some()
            || row.identifier_order.is_some()
            || row.parents[1] != [0; 64]
            || !kind.check_graph_shape(&row.references, row.frontier_applied)
        {
            return Err(Fault::Malformed.into());
        }
        let signer = kind.signer(Authentication {
            owner: row.owner,
            session: row.session,
            public: row.public,
            peer: row.peer,
        })?;
        Self::check_source(signer, row.provenance.role)
    }
}

pub(in crate::archive) fn can_detach(node: &Node) -> bool {
    let Some(kind) = DetachedKind::of(node.kind) else {
        return false;
    };
    if !node.graph_row_is_settled()
        || node.cipher_layout.is_some()
        || node.plain_layout.is_some()
        || node.transcript_layout.is_some()
        || node.identifier_order.is_some()
        || node.parents[1] != [0; 64]
        || !kind.check_graph_shape(&node.references, node.frontier_applied)
    {
        return false;
    }
    let Some(auth) = node.auth else {
        return false;
    };
    if kind
        .signer(auth)
        .and_then(|signer| DetachedKind::check_source(signer, node.origin.provenance().role))
        .is_err()
    {
        return false;
    }
    match node.phase {
        MessagePhase::Applied => {
            node.has_original()
                && node.delete_at.is_none()
                && (kind.is_deletable() || node.deleted_by.is_none())
        }
        MessagePhase::Deleted => kind.is_deletable() && !node.has_original(),
        _ => false,
    }
}
