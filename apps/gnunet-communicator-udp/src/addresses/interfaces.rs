//! Complete interface claims prepared before any live publication state changes.
use super::*;

#[must_use = "Commit after every dependent snapshot projection succeeds, or drop to retain original claims"]
pub(crate) struct InterfaceUpdate<'addresses, 'nat, 'pils> {
    owner: &'addresses mut Addresses<'nat, 'pils>,
    claims: Vec<Claim<'nat>>,
    version: u64,
}

impl InterfaceUpdate<'_, '_, '_> {
    /// All classification, allocation, formatting and counter checks preceded
    /// this exclusive guard. Commit changes intent, never an observed wire fact.
    pub fn commit(self) {
        let Self {
            owner,
            claims,
            version,
        } = self;
        owner.claims = claims;
        if version != owner.version {
            owner.version = version;
            owner.report.clear_feed_written = false;
            for row in &mut owner.rows {
                row.included = row.live
                    && owner
                        .claims
                        .iter()
                        .any(|claim| claim.address == row.address);
            }
        }
    }
}
impl<'nat, 'pils> Addresses<'nat, 'pils> {
    /// Prepare the entire interface replacement without changing claims, local
    /// publication receipts, FEED versions or original NAT callback ownership.
    pub fn prepare_interfaces(
        &mut self,
        addresses: &[SocketAddr],
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<InterfaceUpdate<'_, 'nat, 'pils>, Failure> {
        if self.report.closing {
            return Err(Fault::Closed.into());
        }
        let mut claims = Vec::new();
        claims
            .try_reserve_exact(self.maximum)
            .map_err(|_| Fault::Capacity)?;
        claims.extend(
            self.claims
                .iter()
                .filter(|claim| claim.origin != Origin::Interface)
                .copied(),
        );
        let mut new_rows = 0_u32;
        for &address in addresses {
            if !usable(address)
                || claims
                    .iter()
                    .any(|claim| claim.origin == Origin::Interface && claim.address == address)
            {
                continue;
            }
            if claims.len() == self.maximum {
                return Err(Fault::Capacity.into());
            }
            Text::new(address, false)?;
            Text::new(address, true)?;
            if !self.rows.iter().any(|row| row.address == address) {
                new_rows = new_rows.checked_add(1).ok_or(Fault::Overflow)?;
            }
            claims.push(Claim {
                origin: Origin::Interface,
                address,
                network: classify(address).map_err(Failure::Network)?,
            });
        }
        self.next_id.checked_add(new_rows).ok_or(Fault::Overflow)?;
        let changed = self.rows.iter().any(|row| {
            row.included != (row.live && claims.iter().any(|claim| claim.address == row.address))
        });
        let version = if changed {
            self.version.checked_add(1).ok_or(Fault::Overflow)?
        } else {
            self.version
        };
        Ok(InterfaceUpdate {
            owner: self,
            claims,
            version,
        })
    }
    #[cfg(test)]
    pub fn replace_interfaces(
        &mut self,
        addresses: &[SocketAddr],
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<(), Failure> {
        self.prepare_interfaces(addresses, classify)?.commit();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
