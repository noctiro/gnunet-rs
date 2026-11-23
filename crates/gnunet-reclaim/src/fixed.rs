//! Allocation-free RECLAIM operations over original NAMESTORE rows.

mod consume;
mod deletion;
mod issue;
mod records;
mod revoke;
mod store;

use crate::{
    PresentationList,
    ipc::{Iteration, Response},
};
use gnunet_gnsrecord::ZoneKey;
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;

pub use consume::{
    AttributeAnswer, AttributeLookup, AttributeReference, Authorization, Consume, ConsumeLimits,
    consume_failure,
};
pub use deletion::{Delete, DeleteDependencies, DeletePlan, DeleteScan, RowPresence};
pub use issue::{Issue, IssuedTicket, TicketRow, ValidatedIssue};
#[cfg(feature = "alloc")]
pub(crate) use records::StoredRecord;
pub use records::{IDENTIFIER_LABEL_BYTES, identifier_label, iteration_row};
pub use revoke::{BoundRevoke, Revocation, RevocationScan, Revoke, RevokeChange};
pub use store::{AssignedStore, Store};

/// Credited iteration of current authoritative rows in increasing serial order.
/// The caller binds it to the original connection and private zone, bounds the
/// number of visits per turn, and retains any partially written response.
pub struct Cursor {
    kind: Iteration,
    rid: u32,
    issuer: ZoneKey,
    serial: u64,
    credit: Option<u16>,
}

impl Cursor {
    /// START grants one result. Valid NAMESTORE row serials start at one.
    #[must_use]
    pub const fn new(kind: Iteration, rid: u32, issuer: ZoneKey) -> Self {
        Self {
            kind,
            rid,
            issuer,
            serial: 0,
            credit: Some(1),
        }
    }

    /// Check the family and RID of a control message from the original connection.
    #[must_use]
    pub fn matches(&self, kind: Iteration, rid: u32) -> bool {
        self.kind == kind && self.rid == rid
    }

    /// Grant one result for a matching NEXT. A local write grants no credit.
    pub fn grant_next(&mut self) -> Result<(), Error> {
        let credit = self.credit.as_mut().ok_or(Error::Closed)?;
        *credit = credit.checked_add(1).ok_or(Error::Capacity)?;
        Ok(())
    }

    /// Exclusive lower bound for the next row, only while a result is requested.
    #[must_use]
    pub fn after(&self) -> Option<u64> {
        self.credit
            .filter(|credit| *credit != 0)
            .map(|_| self.serial)
    }

    /// Interpret the next normalized row of the original private zone. A skipped
    /// row moves the cursor without using credit. A parse error changes nothing.
    /// If the caller cannot retain or write the returned response, it must retire
    /// the iterator without reporting normal exhaustion.
    pub fn visit<'a>(
        &mut self,
        serial: u64,
        label: &[u8],
        records: Records<'a>,
    ) -> Result<Option<Response<'a>>, Error> {
        let credit = self.require_credit()?;
        if serial <= self.serial {
            return Err(Error::Stale);
        }
        let result = iteration_row(self.kind, self.rid, self.issuer, label, records)?;
        self.serial = serial;
        self.credit = Some(credit - u16::from(result.is_some()));
        Ok(result)
    }

    /// Report verified provider exhaustion once. STOP and provider failures
    /// retire the cursor without calling this method.
    pub fn finish(&mut self) -> Result<Response<'static>, Error> {
        self.require_credit()?;
        self.credit = None;
        Ok(iteration_end(self.kind, self.rid))
    }

    fn require_credit(&self) -> Result<u16, Error> {
        match self.credit {
            Some(0) => Err(Error::NotReady),
            Some(credit) => Ok(credit),
            None => Err(Error::Closed),
        }
    }
}

/// Construct the official END marker for a naturally exhausted iterator.
#[must_use]
pub const fn iteration_end(kind: Iteration, rid: u32) -> Response<'static> {
    match kind {
        Iteration::Attributes => Response::Attribute {
            rid,
            reserved: 0,
            credential_len: 0,
            identity: None,
            attribute: None,
        },
        Iteration::Credentials => Response::Credential {
            rid,
            identity: None,
            credential: None,
        },
        Iteration::Tickets => Response::Ticket {
            rid,
            ticket: None,
            uri: None,
            presentations: PresentationList::empty(),
        },
    }
}
