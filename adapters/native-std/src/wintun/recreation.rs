//! Recreate only an actually created adapter after its complete old scope retired.
use super::{Adapter, Driver, Origin};
use crate::interfaces::{Identity, RetiredScope, RetirementLimits};
use std::{ffi::OsString, io, os::windows::ffi::OsStringExt};

pub(super) struct Recipe {
    alias: Vec<u16>,
    tunnel_type: Vec<u16>,
}
fn copy(units: &[u16]) -> io::Result<Vec<u16>> {
    let mut value = Vec::new();
    value
        .try_reserve_exact(units.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    value.extend_from_slice(units);
    Ok(value)
}
impl Recipe {
    pub(super) fn new(alias: &[u16], tunnel_type: &[u16]) -> io::Result<Self> {
        Ok(Self {
            alias: copy(alias)?,
            tunnel_type: copy(tunnel_type)?,
        })
    }
}
/// Sealed recreation policy copied from the original provider-created owner.
/// Borrowed adapters cannot manufacture this policy. It retains no adapter or
/// session; the old creator must be released and its scope reconciled first.
pub struct Recreation {
    driver: Driver,
    previous: Identity,
    recipe: Recipe,
}
impl std::fmt::Debug for Recreation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WintunRecreation")
            .field("previous", &self.previous)
            .finish_non_exhaustive()
    }
}
impl Adapter {
    /// Preserve fresh-device policy only when this owner retains the real creator.
    /// Reading it does not release this adapter or authorize a borrowed device's
    /// removal. The returned policy still requires actual old-scope retirement.
    ///
    /// # Errors
    /// Returns allocation failure without changing this original adapter.
    pub fn recreation(&self) -> io::Result<Option<Recreation>> {
        let creator = self.owners.creator().unwrap_or(&self.owners.packet);
        let Some(recipe) = &creator.recipe else {
            return Ok(None);
        };
        Ok(Some(Recreation {
            driver: creator.driver.clone(),
            previous: self.identity.identity().clone(),
            recipe: Recipe::new(&recipe.alias, &recipe.tunnel_type)?,
        }))
    }
}
impl Recreation {
    /// Create a new physical adapter after observing the exact old scope absent.
    /// A random private provider name avoids its foreign-alias displacement
    /// behavior. The configured alias is restored through the exact new GUID's
    /// NetCon object. Caller serializes native administration and owns the finite
    /// recovery deadline; no route, address or packet readiness is inferred.
    ///
    /// # Errors
    /// Refuses another scope, occupied alias/GUID, native enumeration, creation,
    /// GUID mismatch or rename failure. A qualified provisional creator remains
    /// in the error; its eventual void close is not a kernel-removal receipt.
    pub fn create(
        &self,
        retired: &RetiredScope,
        until: std::time::Instant,
    ) -> Result<Adapter, RecreationError> {
        let prepared = (|| -> io::Result<Adapter> {
            deadline(until)?;
            if retired.identity() != &self.previous {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "recreation has another retired scope",
                ));
            }
            self.previous.retired_scope(RetirementLimits::default())?;
            deadline(until)?;
            let guid = self.previous.guid();
            crate::interfaces::require_vacant(&self.recipe.alias, Some(guid))?;
            let mut nonce = [0; 16];
            crate::entropy::fill(&mut nonce)?;
            let mut name = String::from("GNUnet-");
            use std::fmt::Write;
            for byte in nonce {
                write!(&mut name, "{byte:02x}").map_err(io::Error::other)?;
            }
            let tunnel_type =
                OsString::from_wide(&self.recipe.tunnel_type[..self.recipe.tunnel_type.len() - 1]);
            deadline(until)?;
            self.driver
                .create_vacant(name.as_ref(), &tunnel_type, Some(&guid), Some(until))
        })();
        let adapter = prepared.map_err(|error| RecreationError {
            adapter: None,
            error,
        })?;
        self.finish(adapter, until)
    }
    /// Finish alias restoration on the same provisional creator after a refusal.
    /// This never creates another adapter or changes borrowed configuration.
    ///
    /// # Errors
    /// Returns the same actual owner on every deadline, qualification, allocation
    /// or rename refusal. Its eventual close is not a kernel-removal receipt.
    pub fn finish(
        &self,
        mut adapter: Adapter,
        until: std::time::Instant,
    ) -> Result<Adapter, RecreationError> {
        let attempt = (|| -> io::Result<()> {
            deadline(until)?;
            let actual = adapter.port().identity().clone();
            if actual.compartment() != self.previous.compartment()
                || !super::selector::same_guid(actual.guid(), self.previous.guid())
                || adapter.origin() != Origin::Created
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "created Wintun selection differs",
                ));
            }
            let alias = OsString::from_wide(&self.recipe.alias[..self.recipe.alias.len() - 1]);
            let recipe = Box::new(Recipe::new(&self.recipe.alias, &self.recipe.tunnel_type)?);
            deadline(until)?;
            if adapter.port().interface()?.alias != alias {
                actual.rename(&alias, until)?;
            }
            deadline(until)?;
            adapter.owners.packet.recipe = Some(recipe);
            Ok(())
        })();
        match attempt {
            Ok(()) => Ok(adapter),
            Err(error) => Err(RecreationError {
                adapter: Some(Box::new(adapter)),
                error,
            }),
        }
    }
}
fn deadline(until: std::time::Instant) -> io::Result<()> {
    if std::time::Instant::now() >= until {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}
/// Creation refusal retains any actual qualified provisional creator.
#[derive(Debug)]
pub struct RecreationError {
    adapter: Option<Box<Adapter>>,
    error: io::Error,
}
impl RecreationError {
    /// Recover the admitted provisional creator and actual independent cause.
    pub fn into_parts(self) -> (Option<Adapter>, io::Error) {
        (self.adapter.map(|adapter| *adapter), self.error)
    }
}
impl std::fmt::Display for RecreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wintun recreation: {}", self.error)
    }
}
impl std::error::Error for RecreationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
