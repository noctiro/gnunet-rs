//! Bounded capture-time selection over complete immutable interface observations.
use crate::interfaces::Identity;
use std::io;

pub(super) const MAX_INTERFACES: usize = 4096;
pub(super) struct View {
    since: i64,
    entries: Vec<Identity>,
}
impl View {
    pub fn new(since: i64, mut entries: Vec<Identity>) -> io::Result<Self> {
        if since < 0 || entries.len() > MAX_INTERFACES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        entries.sort_unstable_by_key(Identity::index);
        if entries.iter().any(|entry| entry.index() == 0)
            || entries
                .windows(2)
                .any(|pair| pair[0].index() == pair[1].index())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ambiguous capture interface observation",
            ));
        }
        Ok(Self { since, entries })
    }
    fn get(&self, index: u32) -> io::Result<&Identity> {
        self.entries
            .binary_search_by_key(&index, Identity::index)
            .map(|at| &self.entries[at])
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "captured interface absent from its original observation",
                )
            })
    }
}
pub(super) struct History {
    current: View,
    previous: Option<View>,
}
impl History {
    pub fn new(since: i64, entries: Vec<Identity>) -> io::Result<Self> {
        Ok(Self {
            current: View::new(since, entries)?,
            previous: None,
        })
    }
    pub fn publish(&mut self, candidate: View) -> io::Result<Option<View>> {
        let since = candidate.since;
        if since < self.current.since {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capture observation clock moved backwards",
            ));
        }
        if candidate.entries != self.current.entries {
            if since == self.current.since {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "changed capture interfaces share an ambiguous observation tick",
                ));
            }
            let previous = std::mem::replace(&mut self.current, candidate);
            return Ok(self.previous.replace(previous));
        }
        Ok(Some(candidate))
    }
    #[cfg(test)]
    fn refresh(&mut self, since: i64, entries: Vec<Identity>) -> io::Result<()> {
        self.publish(View::new(since, entries)?)?;
        Ok(())
    }
    pub fn get(&self, captured: i64, index: u32) -> io::Result<&Identity> {
        if captured > self.current.since {
            self.current.get(index)
        } else if captured == self.current.since {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "capture lies on an ambiguous observation boundary",
            ))
        } else if let Some(previous) = &self.previous
            && captured > previous.since
        {
            previous.get(index)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "capture predates retained interface observations",
            ))
        }
    }
}

#[cfg(test)]
#[path = "observations/tests.rs"]
mod tests;
