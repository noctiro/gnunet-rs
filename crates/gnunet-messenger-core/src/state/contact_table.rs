//! Shared generational contact table with owned or caller-owned cells.

use super::ContactRow;
use crate::{
    Error,
    slots::{Entry, EntryCell, Table},
    storage::Backing,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{fmt, mem::size_of};
use gnunet_types::Error as Fault;

/// One opaque cell in caller-owned contact storage.
pub struct ContactCell(Entry<ContactRow>);

impl ContactCell {
    /// An empty cell ready for a new contact table.
    pub const fn empty() -> Self {
        Self(Entry::vacant())
    }
}

impl fmt::Debug for ContactCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContactCell([REDACTED])")
    }
}

impl EntryCell<ContactRow> for ContactCell {
    fn entry(&self) -> &Entry<ContactRow> {
        &self.0
    }

    fn entry_mut(&mut self) -> &mut Entry<ContactRow> {
        &mut self.0
    }
}

pub(crate) struct BorrowedContacts<'id>(&'id mut [ContactCell]);

impl AsRef<[ContactCell]> for BorrowedContacts<'_> {
    fn as_ref(&self) -> &[ContactCell] {
        self.0
    }
}

impl AsMut<[ContactCell]> for BorrowedContacts<'_> {
    fn as_mut(&mut self) -> &mut [ContactCell] {
        self.0
    }
}

impl Drop for BorrowedContacts<'_> {
    fn drop(&mut self) {
        // Drop each live row and its zeroizing name before returning the cells.
        self.0.fill_with(ContactCell::empty);
    }
}

pub(crate) type ContactTable<'id> =
    Table<ContactRow, Backing<ContactCell, BorrowedContacts<'id>>, ContactCell>;

impl<'id> ContactTable<'id> {
    #[cfg(feature = "alloc")]
    pub fn new(limit: usize) -> Result<Self, Error> {
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        cells.resize_with(limit, ContactCell::empty);
        Ok(Self::start(Backing::Owned(cells)))
    }

    pub fn fixed(cells: &'id mut [ContactCell], limit: usize) -> Result<Self, Error> {
        if cells.len() != limit {
            return Err(Fault::Capacity.into());
        }
        cells.fill_with(ContactCell::empty);
        Ok(Self::start(Backing::fixed(BorrowedContacts(cells))))
    }

    pub fn required_bytes(limit: usize) -> Result<usize, Error> {
        limit
            .checked_mul(size_of::<ContactCell>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        Self::required_bytes(self.storage().capacity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check the caller-owned contact buffer's charge and reset after drop"
    )]
    fn dropping_contacts_returns_empty_cells() -> Result<(), Error> {
        let mut cells = [ContactCell::empty()];
        assert!(matches!(
            ContactTable::fixed(&mut cells, 2),
            Err(Error::Protocol(Fault::Capacity))
        ));
        {
            let mut table = ContactTable::fixed(&mut cells, 1)?;
            assert_eq!(table.bytes()?, ContactTable::required_bytes(1)?);
            let contact = ContactRow {
                key: [1; 36],
                name: None,
                anonymous_context: None,
                #[cfg(feature = "alloc")]
                local: false,
                canonical: true,
                rooms: 0,
            };
            table.insert(contact).map_err(|(error, _)| error)?;
        }
        // Open the returned storage without reinitializing it, to observe Drop.
        let table = ContactTable::start(Backing::fixed(BorrowedContacts(&mut cells)));
        assert!(table.slot_at(0).is_none());
        assert_eq!(table.next_key()?.generation, 1);
        Ok(())
    }

    #[cfg(feature = "alloc")]
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check name replacement and slot retirement with bounded storage"
    )]
    fn fixed_name_replacement_and_retirement_preserve_pool_capacity() -> Result<(), Error> {
        use crate::{
            Instance, OriginalPool, OriginalPoolInstance, OriginalSlot, model::structural_core,
            state::ByteStore,
        };

        let mut instance = Instance::new();
        let mut name_instance = OriginalPoolInstance::new();
        let mut slots = [OriginalSlot::EMPTY; 2];
        let mut bytes = [0; 6];
        let mut core = structural_core(&mut instance)?;
        core.names = ByteStore::Fixed(OriginalPool::new(
            &mut name_instance,
            &mut slots,
            &mut bytes,
        ));
        let baseline = core.charged_bytes();
        let room = core.room([1; 64], None)?;
        let contact = |key| ContactRow {
            key: [key; 36],
            name: None,
            anonymous_context: None,
            #[cfg(feature = "alloc")]
            local: false,
            canonical: true,
            rooms: 0,
        };
        let first = core
            .contacts
            .insert(contact(1))
            .map_err(|(error, _)| error)?;
        let second = core
            .contacts
            .insert(contact(2))
            .map_err(|(error, _)| error)?;
        core.replace_contact_name(first, b"foo")?;
        core.replace_contact_name(second, b"bar")?;
        let charged = core.charged_bytes();
        assert_eq!(
            core.replace_contact_name(first, b"long"),
            Err(Fault::Capacity.into())
        );
        assert_eq!(core.contact_name_at(first)?, Some(b"foo".as_slice()));
        assert_eq!(core.charged_bytes(), charged);
        core.replace_contact_name(first, b"")?;
        assert_eq!(core.contact_name_at(first)?, Some(b"".as_slice()));
        core.replace_contact_name(second, b"longer")?;
        assert_eq!(core.charged_bytes(), charged);

        core.forget_room(room)?;
        assert_eq!(core.charged_bytes(), baseline);
        let replacement = core
            .contacts
            .insert(contact(3))
            .map_err(|(error, _)| error)?;
        assert_eq!(core.contact_name_at(replacement)?, None);
        core.replace_contact_name(replacement, b"reuse!")?;
        let more = core
            .contacts
            .insert(contact(4))
            .map_err(|(error, _)| error)?;
        core.replace_contact_name(more, b"")?;
        Ok(())
    }
}
