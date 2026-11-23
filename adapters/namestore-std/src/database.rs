//! One service or offline owner of the original NAMESTORE writer lease.
mod configuration;
#[cfg(test)]
mod tests;
pub use configuration::Options;

use crate::{Error, backend, critical_type, snapshot};
use gnunet_namestore::{Core, Limits, RecordType};
use gnunet_types::Error as Fault;
use std::sync::Arc;

/// One explicit offline operation on the selected Rust NAMESTORE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Maintenance {
    /// Initialize an absent canonical image, or validate an existing one.
    Initialize,
    /// Publish an empty inventory in place of the original canonical image.
    Reset,
}

/// A qualified NAMESTORE and its loaded authority under one exclusive lease.
/// Only [Options::open] constructs this pair.
pub struct Database {
    store: backend::Store,
    loaded: backend::Loaded,
    limits: Limits,
}

/// Validated service inventory and the same exclusive store that supplied it.
pub struct Recovered {
    core: Core,
    store: backend::Store,
    recovered_temporaries: usize,
}

impl Recovered {
    /// Number of recognized pending snapshots retired during the original open.
    #[must_use]
    pub const fn recovered_temporaries(&self) -> usize {
        self.recovered_temporaries
    }

    /// Transfer the recovered inventory and its writer to the service frontend.
    #[must_use]
    pub fn into_parts(self) -> (Core, backend::Store) {
        (self.core, self.store)
    }
}

impl Options {
    /// Open the configured private store under the service's exclusive lease.
    pub fn open(&self) -> Result<Database, Error> {
        gnunet_service_runtime::private_parents(&self.directory)?;
        let (store, loaded) =
            backend::Store::open(backend::Namespace::Namestore, &self.directory, self.backend)
                .map_err(|error| Error::Storage(Arc::new(error)))?;
        Ok(Database {
            store,
            loaded,
            limits: self.limits,
        })
    }
}

impl Database {
    /// Recover service authority. A new store commits an empty canonical image
    /// before returning. Existing marked stores require an intact image.
    pub fn recover(self) -> Result<Recovered, Error> {
        self.recover_with(critical_type)
    }

    /// Recover with an embedder's original record registry. The same predicate
    /// remains on the recovered core for its future request handling.
    pub fn recover_with(self, critical: fn(RecordType) -> bool) -> Result<Recovered, Error> {
        let Self {
            mut store,
            loaded,
            limits,
        } = self;
        let recovered_temporaries = loaded.recovered_temporaries();
        let core = if store.generation() == 0 {
            if !loaded.created_directory() || !loaded.into_body().is_empty() {
                return Err(Fault::Storage.into());
            }
            publish_empty(&mut store, limits, critical)?
        } else {
            recover_inventory(loaded, limits, critical)?
        };
        Ok(Recovered {
            core,
            store,
            recovered_temporaries,
        })
    }

    /// Complete one offline action while holding the original writer lease.
    /// Reset replaces the original image in one transaction. Its error preserves
    /// the store's publication exposure, including an uncertain replacement.
    pub fn maintain(self, action: Maintenance) -> Result<(), Error> {
        let Self {
            mut store,
            loaded,
            limits,
        } = self;
        match action {
            Maintenance::Initialize if store.generation() != 0 => {
                let _validated = recover_inventory(loaded, limits, critical_type)?;
            }
            Maintenance::Initialize | Maintenance::Reset => {
                // Erase the original secret snapshot before publishing the new
                // empty authority. The writer still pins the same native file.
                drop(loaded);
                let _empty = publish_empty(&mut store, limits, critical_type)?;
            }
        }
        Ok(())
    }
}

fn recover_inventory(
    loaded: backend::Loaded,
    limits: Limits,
    critical: fn(RecordType) -> bool,
) -> Result<Core, Error> {
    let rows = snapshot::decode(loaded.into_body(), limits)?;
    Ok(Core::new(limits, rows, critical)?)
}

fn publish_empty(
    store: &mut backend::Store,
    limits: Limits,
    critical: fn(RecordType) -> bool,
) -> Result<Core, Error> {
    let core = Core::new(limits, Vec::new(), critical)?;
    let image = snapshot::encode(&core.snapshot()?, snapshot::EMPTY_BYTES)?;
    let generation = store.generation();
    let receipt = store.commit(generation, image).map_err(Error::Storage)?;
    if receipt.namespace() != backend::Namespace::Namestore
        || generation.checked_add(1) != Some(receipt.generation())
        || store.generation() != receipt.generation()
    {
        return Err(Fault::OutcomeUnknown.into());
    }
    Ok(core)
}
