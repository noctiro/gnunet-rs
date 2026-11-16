//! Read-only complete marker discovery. Results are selectors, never TUN owners.
use super::{names, read_marker_at};
use crate::{
    platform::control_socket,
    recovery::{Intent, Record, marker::Matches},
};
use std::{io, os::fd::OwnedFd};
pub(crate) fn find(intent: &Intent) -> io::Result<Option<Record>> {
    let socket: OwnedFd = control_socket()?.into();
    let inventory = names::snapshot()?;
    let mut matching = Matches::default();
    for row in inventory {
        let name = crate::recovery::read_name(&row.bytes)?;
        let record = match read_marker_at(&socket, name) {
            Ok(record) => record,
            Err(error) if error.raw_os_error() == Some(libc::ENOMSG) => None,
            Err(error) => return Err(error),
        };
        if let Some(record) = record {
            matching.observe(intent, &row.bytes, row.index, record)?;
        }
    }
    matching.selected()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_marker_inventory_is_read_only_and_grants_no_owner() -> io::Result<()> {
        let mut nonce = [0; 32];
        gnunet_native::entropy::fill(&mut nonce)?;
        let intent = Intent::for_marker_test(nonce);
        if find(&intent)?.is_some() {
            return Err(io::Error::other(
                "unrelated interface metadata matched a fresh allocation nonce",
            ));
        }
        Ok(())
    }
}
