use crate::{Attribute, AttributeList, Credential};
use core::{fmt, iter::FusedIterator};

/// One credential and the attributes selected for it in a ticket request.
#[derive(Clone, Copy)]
pub struct PresentationRequest<'a> {
    credential: Credential<'a>,
    attributes: AttributeList<'a>,
}

impl<'a> PresentationRequest<'a> {
    /// Scope a ticket's selection to the original credential identifier.
    pub fn new(credential: Credential<'a>, attributes: AttributeList<'a>) -> Self {
        let attributes = if credential.id.is_zero() {
            AttributeList::empty()
        } else {
            attributes
        };
        Self {
            credential,
            attributes,
        }
    }

    /// Original credential bytes and metadata.
    pub const fn credential(self) -> Credential<'a> {
        self.credential
    }

    /// Attributes that reference this credential, in the original request order.
    /// A credential with the zero identifier has no associated attributes.
    pub fn selected_attributes(self) -> impl FusedIterator<Item = Attribute<'a>> {
        let id = self.credential.id;
        self.attributes
            .iter()
            .filter(move |attribute| attribute.credential == id)
    }
}

impl fmt::Debug for PresentationRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentationRequest")
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}
