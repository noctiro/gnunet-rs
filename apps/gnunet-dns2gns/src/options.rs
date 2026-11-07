//! Mandatory numeric recursive upstream; -d is not a daemon option.
use crate::Cause;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::net::IpAddr;
pub(super) struct Selection {
    dns: Target<Option<Vec<u8>>>,
}
impl Selection {
    pub(super) fn new() -> Self {
        Self {
            dns: Target::new(None),
        }
    }
    pub(super) fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::string(
            b'd',
            b"dns",
            b"IP",
            b"Numeric recursive DNS resolver IP address (required)",
            self.dns.clone(),
        ));
        options
    }
    pub(super) fn finish(self, args: &[Vec<u8>]) -> Result<IpAddr, Cause> {
        if !args.is_empty() {
            return Err("gnunet-dns2gns accepts -d/--dns IP and no positional arguments".into());
        }
        let bytes = self
            .dns
            .get()?
            .ok_or("-d/--dns numeric upstream IP is required")?;
        if bytes.is_empty() || bytes.len() > 64 || bytes.contains(&0) {
            return Err("invalid numeric upstream IP extent".into());
        }
        Ok(std::str::from_utf8(&bytes)?.parse()?)
    }
}
