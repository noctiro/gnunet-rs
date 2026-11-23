//! Bounded identity inventory with borrowed publication and no heap storage.

use crate::{ChangeKind, Code, MAX_NAME_BYTES, Mutation, SecretKey, SecretKeyView, names};
use gnunet_types::Error;
use gnunet_wire::official::identity::Response;
use zeroize::Zeroize;

#[cfg(test)]
mod tests;

/// Caller-owned lowercase, decomposition and canonical ordering scratch.
pub struct NameScratch<const N: usize> {
    lowered: [u32; N],
    normalized: [u32; N],
    ordering: [u32; N],
}

impl<const N: usize> NameScratch<N> {
    /// Empty storage for a product arena.
    pub const EMPTY: Self = Self {
        lowered: [0; N],
        normalized: [0; N],
        ordering: [0; N],
    };

    /// Erase temporary name data.
    pub fn clear(&mut self) {
        self.lowered.zeroize();
        self.normalized.zeroize();
        self.ordering.zeroize();
    }
}

struct Name<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Name<N> {
    fn normalized(input: &[u8], scratch: &mut NameScratch<N>) -> Result<Self, Error> {
        let mut name = Self {
            bytes: [0; N],
            len: 0,
        };
        name.len = names::normalize_into(
            input,
            &mut name.bytes,
            &mut scratch.lowered,
            &mut scratch.normalized,
            &mut scratch.ordering,
        )
        .map_err(|error| {
            if error == Error::Capacity {
                Error::TooLarge
            } else {
                error
            }
        })?;
        Ok(name)
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

struct Ego<const N: usize> {
    name: Name<N>,
    key: SecretKey,
}

impl<const N: usize> Ego<N> {
    fn view(&self) -> EgoRef<'_> {
        EgoRef {
            name: self.name.bytes(),
            key: &self.key,
        }
    }
}

/// A borrowed canonical row. The private key remains in its original owner.
#[derive(Clone, Copy)]
pub struct EgoRef<'a> {
    /// Canonical UTF-8 name without its final wire NUL.
    pub name: &'a [u8],
    /// Opaque private key. A caller must explicitly expose its sensitive bytes.
    pub key: &'a SecretKey,
}

impl<'a> EgoRef<'a> {
    /// Borrow the official UPDATE for initialization, lookup or a mutation.
    pub fn response(self) -> Result<Response<'a>, Error> {
        Ok(Response::Update {
            name: Some(self.name),
            key: self.key.view()?,
        })
    }
}

/// Fixed rows with stable key slots and a separate newest-first index.
pub struct Inventory<const R: usize, const N: usize> {
    rows: [Option<Ego<N>>; R],
    order: [usize; R],
    len: usize,
    needs_recovery: bool,
}

impl<const R: usize, const N: usize> Inventory<R, N> {
    /// An empty, unborrowed inventory ready for startup recovery.
    pub const EMPTY: Self = Self {
        rows: [const { None }; R],
        order: [0; R],
        len: 0,
        needs_recovery: false,
    };

    /// Discard the original rows before recovering a complete durable inventory.
    pub fn clear(&mut self) {
        self.erase_rows();
        self.needs_recovery = false;
    }

    fn erase_rows(&mut self) {
        for row in &mut self.rows {
            *row = None;
        }
        self.order.fill(0);
        self.len = 0;
    }

    /// Append a durable row, in its persisted newest-first order.
    /// Active service ownership exclusively borrows the inventory.
    ///
    /// # Errors
    /// Refuses a noncanonical or duplicate name or exhausted fixed storage.
    pub fn restore(
        &mut self,
        name: &[u8],
        key: SecretKeyView<'_>,
        scratch: &mut NameScratch<N>,
    ) -> Result<(), Error> {
        if self.needs_recovery {
            return Err(Error::OutcomeUnknown);
        }
        if N > MAX_NAME_BYTES {
            return Err(Error::InvalidInput);
        }
        let canonical = Name::normalized(name, scratch)?;
        if canonical.bytes() != name {
            return Err(Error::InvalidInput);
        }
        if self.position(name).is_some() {
            return Err(Error::Conflict);
        }
        let slot = self.vacant().ok_or(Error::Capacity)?;
        let key = SecretKey::from_serialized(key.expose_serialized())?;
        self.rows[slot] = Some(Ego {
            name: canonical,
            key,
        });
        self.order[self.len] = slot;
        self.len += 1;
        Ok(())
    }

    fn vacant(&self) -> Option<usize> {
        self.rows.iter().position(Option::is_none)
    }

    fn row(&self, index: usize) -> Option<&Ego<N>> {
        let &slot = self.order.get(..self.len)?.get(index)?;
        self.rows.get(slot)?.as_ref()
    }

    fn position(&self, name: &[u8]) -> Option<usize> {
        (0..self.len).find(|&index| self.row(index).is_some_and(|row| row.name.bytes() == name))
    }

    fn apply<'a>(
        rows: &'a mut [Option<Ego<N>>; R],
        indices: &mut [usize; R],
        len: &mut usize,
        plan: Plan<N>,
    ) -> Result<Change<'a>, Error> {
        match plan {
            Plan::Create { slot, ego } => {
                let row = rows
                    .get_mut(slot)
                    .filter(|row| row.is_none())
                    .ok_or(Error::Conflict)?;
                let order = indices.get_mut(..=*len).ok_or(Error::Conflict)?;
                order.rotate_right(1);
                order[0] = slot;
                *len += 1;
                Ok(Change::Created(row.insert(ego).view()))
            }
            Plan::Rename { index, name } => {
                let slot = *indices
                    .get(..*len)
                    .and_then(|order| order.get(index))
                    .ok_or(Error::Conflict)?;
                let row = rows
                    .get_mut(slot)
                    .and_then(Option::as_mut)
                    .ok_or(Error::Conflict)?;
                row.name = name;
                Ok(Change::Renamed(row.view()))
            }
            Plan::Delete { index } => {
                let order = indices
                    .get_mut(..*len)
                    .and_then(|order| order.get_mut(index..))
                    .ok_or(Error::Conflict)?;
                let slot = *order.first().ok_or(Error::Conflict)?;
                let Ego { key, .. } = rows
                    .get_mut(slot)
                    .and_then(Option::take)
                    .ok_or(Error::Conflict)?;
                order.rotate_left(1);
                *len -= 1;
                indices[*len] = 0;
                Ok(Change::Deleted(key))
            }
        }
    }
}

enum Plan<const N: usize> {
    Create { slot: usize, ego: Ego<N> },
    Rename { index: usize, name: Name<N> },
    Delete { index: usize },
}

/// A newest-first stream of either committed rows or one proposed after-image.
pub struct Rows<'a, const R: usize, const N: usize> {
    inventory: &'a Inventory<R, N>,
    plan: Option<&'a Plan<N>>,
    next: usize,
}

impl<'a, const R: usize, const N: usize> Rows<'a, R, N> {
    fn total(&self) -> usize {
        match self.plan {
            Some(Plan::Create { .. }) => self.inventory.len + 1,
            Some(Plan::Delete { .. }) => self.inventory.len - 1,
            _ => self.inventory.len,
        }
    }

    fn at(&self, index: usize) -> Option<EgoRef<'a>> {
        match self.plan {
            Some(Plan::Create { ego, .. }) if index == 0 => Some(ego.view()),
            Some(Plan::Create { .. }) => self.inventory.row(index - 1).map(Ego::view),
            Some(Plan::Rename {
                index: changed,
                name,
            }) if index == *changed => {
                let row = self.inventory.row(index)?;
                Some(EgoRef {
                    name: name.bytes(),
                    key: &row.key,
                })
            }
            Some(Plan::Delete { index: removed }) if index >= *removed => {
                self.inventory.row(index + 1).map(Ego::view)
            }
            _ => self.inventory.row(index).map(Ego::view),
        }
    }
}

impl<'a, const R: usize, const N: usize> Iterator for Rows<'a, R, N> {
    type Item = EgoRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.total() {
            return None;
        }
        let row = self.at(self.next)?;
        self.next += 1;
        Some(row)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total() - self.next;
        (remaining, Some(remaining))
    }
}

impl<const R: usize, const N: usize> ExactSizeIterator for Rows<'_, R, N> {}
impl<const R: usize, const N: usize> core::iter::FusedIterator for Rows<'_, R, N> {}

/// Disposition of a failed native publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitError {
    /// The original after-image is known not to have been published.
    Failed(Error),
    /// Publication may have happened and the original store must be reopened.
    OutcomeUnknown,
}

/// One committed change, borrowed where the row still exists and owned on delete.
pub enum Change<'a> {
    /// The newly created ego, preceding older rows.
    Created(EgoRef<'a>),
    /// The renamed ego, retaining its key and initial position.
    Renamed(EgoRef<'a>),
    /// The removed ego's original key, zeroized on drop.
    Deleted(SecretKey),
}

impl Change<'_> {
    /// Original mutation kind for native reply ordering.
    pub const fn kind(&self) -> ChangeKind {
        match self {
            Self::Created(_) => ChangeKind::Create,
            Self::Renamed(_) => ChangeKind::Rename,
            Self::Deleted(_) => ChangeKind::Delete,
        }
    }

    /// Borrow the official change notification.
    pub fn response(&self) -> Result<Response<'_>, Error> {
        match self {
            Self::Created(ego) | Self::Renamed(ego) => ego.response(),
            Self::Deleted(key) => Ok(Response::Update {
                name: None,
                key: key.view()?,
            }),
        }
    }
}

#[derive(Clone, Copy)]
enum State {
    Live,
    Closed,
    Fenced,
}

/// Receives private rows in the original persisted newest-first order.
pub type RestoreRow<'load> = dyn FnMut(&[u8], SecretKeyView<'_>) -> Result<(), Error> + 'load;

/// A running service's exclusive borrow of the qualified original inventory.
pub struct Owner<'memory, const R: usize, const N: usize> {
    inventory: &'memory mut Inventory<R, N>,
    state: State,
}

impl<'memory, const R: usize, const N: usize> Owner<'memory, R, N> {
    /// Start a service after loading all durable rows into its inventory.
    ///
    /// # Errors
    /// Refuses a name budget larger than the official UPDATE format.
    pub fn new(inventory: &'memory mut Inventory<R, N>) -> Result<Self, Error> {
        if inventory.needs_recovery {
            return Err(Error::OutcomeUnknown);
        }
        if N > MAX_NAME_BYTES {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            inventory,
            state: State::Live,
        })
    }

    /// Erase original rows and close this owner. Uncertainty remains fenced.
    pub fn clear(&mut self) {
        self.inventory.erase_rows();
        if matches!(self.state, State::Live) {
            self.state = State::Closed;
        }
    }

    /// Admit a closed owner only after loading a complete durable inventory.
    /// The loader visits each row synchronously. A partial image is discarded.
    ///
    /// # Errors
    /// Rejects live or fenced owners and propagates loader errors. An unknown
    /// durable outcome keeps the inventory fenced until separate recovery.
    pub fn restart(
        &mut self,
        scratch: &mut NameScratch<N>,
        load: impl FnOnce(&mut RestoreRow<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self.state {
            State::Closed => (),
            State::Live => return Err(Error::Conflict),
            State::Fenced => return Err(Error::OutcomeUnknown),
        }
        let mut visited = Ok(());
        let loaded = load(&mut |name, key| {
            visited = visited.and_then(|()| self.inventory.restore(name, key, scratch));
            visited
        });
        let result = loaded.and(visited);
        scratch.clear();
        match result {
            Ok(()) => self.state = State::Live,
            Err(error) => {
                self.inventory.erase_rows();
                if error == Error::OutcomeUnknown {
                    self.state = State::Fenced;
                    self.inventory.needs_recovery = true;
                }
            }
        }
        result
    }

    fn live(&self) -> Result<(), Error> {
        match self.state {
            State::Live => Ok(()),
            State::Closed => Err(Error::Closed),
            State::Fenced => Err(Error::OutcomeUnknown),
        }
    }

    /// Enumerate the committed inventory in official newest-first order.
    pub fn egos(&self) -> Result<Rows<'_, R, N>, Error> {
        self.live()?;
        Ok(Rows {
            inventory: self.inventory,
            plan: None,
            next: 0,
        })
    }

    /// Exact lookup uses C-locale ASCII-insensitive matching. Suffix lookup is
    /// case sensitive and selects the longest whole-name or dot-boundary match.
    pub fn lookup(&self, name: &[u8], suffix: bool) -> Result<Option<EgoRef<'_>>, Error> {
        let rows = self.egos()?;
        Ok(names::lookup(name, suffix, rows.map(|row| row.name))?
            .and_then(|index| self.inventory.row(index))
            .map(Ego::view))
    }

    /// Qualify one mutation without changing the original committed inventory.
    /// The returned authority holds the exclusive borrow until it is dropped
    /// or settled by synchronous publication.
    pub fn prepare(
        &mut self,
        mutation: Mutation<'_>,
        scratch: &mut NameScratch<N>,
    ) -> Result<Decision<'_, 'memory, R, N>, Error> {
        self.live()?;
        match self.plan(mutation, scratch) {
            Ok(plan) => Ok(Decision::Prepared(Prepared { owner: self, plan })),
            Err(Refusal::Code(code)) => Ok(Decision::Immediate(code)),
            Err(Refusal::Error(error)) => Err(error),
        }
    }

    fn plan(
        &self,
        mutation: Mutation<'_>,
        scratch: &mut NameScratch<N>,
    ) -> Result<Plan<N>, Refusal> {
        match mutation {
            Mutation::Create { name, key } => {
                let name = normalize(name, scratch)?;
                self.require_vacant_name(&name)?;
                let slot = self
                    .inventory
                    .vacant()
                    .ok_or(Refusal::Error(Error::Capacity))?;
                let key =
                    SecretKey::from_serialized(key.expose_serialized()).map_err(Refusal::Error)?;
                Ok(Plan::Create {
                    slot,
                    ego: Ego { name, key },
                })
            }
            Mutation::Rename { old, new } => {
                let name = normalize(new, scratch)?;
                let old = normalize(old, scratch)?;
                self.require_vacant_name(&name)?;
                let index = self.require_existing_name(&old)?;
                Ok(Plan::Rename { index, name })
            }
            Mutation::Delete { name } => {
                let name = normalize(name, scratch)?;
                let index = self.require_existing_name(&name)?;
                Ok(Plan::Delete { index })
            }
        }
    }

    fn require_vacant_name(&self, name: &Name<N>) -> Result<(), Refusal> {
        if self.inventory.position(name.bytes()).is_some() {
            Err(Refusal::Code(Code::NAME_CONFLICT))
        } else {
            Ok(())
        }
    }

    fn require_existing_name(&self, name: &Name<N>) -> Result<usize, Refusal> {
        self.inventory
            .position(name.bytes())
            .ok_or(Refusal::Code(Code::NOT_FOUND))
    }
}

enum Refusal {
    Code(Code),
    Error(Error),
}

fn normalize<const N: usize>(
    input: &[u8],
    scratch: &mut NameScratch<N>,
) -> Result<Name<N>, Refusal> {
    Name::normalized(input, scratch).map_err(|error| match error {
        Error::InvalidInput | Error::TooLarge => Refusal::Code(Code::INVALID),
        error => Refusal::Error(error),
    })
}

/// Either a business rejection or an original pending publication.
pub enum Decision<'owner, 'memory, const R: usize, const N: usize> {
    /// Official refusal before publication; no mutation is staged.
    Immediate(Code),
    /// Exclusive authority for the original, fully qualified after-image.
    Prepared(Prepared<'owner, 'memory, R, N>),
}

/// Original prepared mutation. Dropping it before publication leaves the
/// committed inventory unchanged and erases any owned imported key.
#[must_use]
pub struct Prepared<'owner, 'memory, const R: usize, const N: usize> {
    owner: &'owner mut Owner<'memory, R, N>,
    plan: Plan<N>,
}

impl<'owner, const R: usize, const N: usize> Prepared<'owner, '_, R, N> {
    /// Lend the after-image to the original synchronous persistence owner.
    /// Success permits in-memory publication. Known failure or an abandoned
    /// preparation preserves the original inventory.
    ///
    /// # Errors
    /// Reports the provider's known failure. An unknown durable result fences
    /// the current inventory until a new service recovers actual media state.
    pub fn persist(
        self,
        publish: impl FnOnce(Rows<'_, R, N>) -> Result<(), CommitError>,
    ) -> Result<Change<'owner>, Error> {
        let Self { owner, plan } = self;
        let Owner { inventory, state } = owner;
        match publish(Rows {
            inventory: &**inventory,
            plan: Some(&plan),
            next: 0,
        }) {
            Ok(()) => (),
            Err(CommitError::OutcomeUnknown | CommitError::Failed(Error::OutcomeUnknown)) => {
                *state = State::Fenced;
                inventory.needs_recovery = true;
                return Err(Error::OutcomeUnknown);
            }
            Err(CommitError::Failed(error)) => return Err(error),
        }
        let Inventory {
            rows,
            order,
            len,
            needs_recovery,
        } = &mut **inventory;
        match Inventory::apply(rows, order, len, plan) {
            Ok(change) => Ok(change),
            Err(_) => {
                *state = State::Fenced;
                *needs_recovery = true;
                Err(Error::OutcomeUnknown)
            }
        }
    }
}
