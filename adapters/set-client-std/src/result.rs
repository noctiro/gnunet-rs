//! Mode-bound result interpretation; control markers never manufacture elements.
use crate::{Element, ElementOwned, Error, ResultMode, Status};

/// One result of an original SET operation.
///
/// Element variants preserve the exact application type and bytes, including
/// a zero-length value. Status-only variants carry no application element.
pub enum ResultValue {
    /// Ordinary element in FULL, REMOVED or ADDED mode.
    Element(ElementOwned),
    /// Element added to the local set in SYMMETRIC mode.
    AddLocal(ElementOwned),
    /// Element added to the remote set in SYMMETRIC mode.
    AddRemote(ElementOwned),
    /// Original operation failed.
    Failure,
    /// Nonterminal half-completion notification.
    HalfDone,
    /// Original operation completed.
    Done,
}

impl ResultValue {
    pub(crate) fn decode(
        mode: ResultMode,
        status: Status,
        element: Element<'_>,
    ) -> Result<Self, Error> {
        // The C API ignores the element fields on final statuses. Do the same
        // without allocating or exposing those fields as an application value.
        Ok(match status {
            Status::Failure => Self::Failure,
            Status::HalfDone => Self::HalfDone,
            Status::Done => Self::Done,
            Status::Ok if mode != ResultMode::Symmetric => {
                Self::Element(ElementOwned::copy(element)?)
            }
            Status::AddLocal if mode == ResultMode::Symmetric => {
                Self::AddLocal(ElementOwned::copy(element)?)
            }
            Status::AddRemote if mode == ResultMode::Symmetric => {
                Self::AddRemote(ElementOwned::copy(element)?)
            }
            _ => return Err(Error::UnexpectedResult { mode, status }),
        })
    }

    /// Public status corresponding to this value.
    #[must_use]
    pub const fn status(&self) -> Status {
        match self {
            Self::Element(_) => Status::Ok,
            Self::AddLocal(_) => Status::AddLocal,
            Self::AddRemote(_) => Status::AddRemote,
            Self::Failure => Status::Failure,
            Self::HalfDone => Status::HalfDone,
            Self::Done => Status::Done,
        }
    }

    /// Original application element; a marker is `None`, an empty value is `Some`.
    #[must_use]
    pub const fn element(&self) -> Option<&ElementOwned> {
        match self {
            Self::Element(element) | Self::AddLocal(element) | Self::AddRemote(element) => {
                Some(element)
            }
            Self::Failure | Self::HalfDone | Self::Done => None,
        }
    }
}
