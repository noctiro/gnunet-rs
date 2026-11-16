//! Frozen native address scope used by startup state retirement and monitoring.
use gnunet_native::interfaces::InterfaceAddress;
use std::{cmp::Ordering, io};

pub(super) struct Scope(Vec<InterfaceAddress>);

fn compare(left: &InterfaceAddress, right: &InterfaceAddress) -> Ordering {
    left.name
        .cmp(&right.name)
        .then_with(|| left.index.cmp(&right.index))
        .then_with(|| left.address.cmp(&right.address))
}

impl Scope {
    pub fn new(mut rows: Vec<InterfaceAddress>) -> Self {
        rows.sort_unstable_by(compare);
        rows.dedup_by(|left, right| compare(left, right).is_eq());
        Self(rows)
    }

    pub fn require_same(&self, current: &Self) -> io::Result<()> {
        if self.0.len() != current.0.len()
            || !self
                .0
                .iter()
                .zip(&current.0)
                .all(|(left, right)| compare(left, right).is_eq())
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "PF original native address scope changed; startup state retirement must be repeated",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
