//! Read-only native configuration qualification; never sends a DNS query.
#![cfg(windows)]
use gnunet_native::{dns, paths};
use std::io;
#[test]
fn native_system_directory_and_dns_snapshot_are_bounded() -> io::Result<()> {
    let directory = paths::system_directory()?;
    if !directory.is_absolute() || !paths::exists(&directory)? {
        return Err(io::Error::other("invalid native system directory"));
    }
    let databases = paths::internet_database_directory()?;
    if !databases.is_absolute() {
        return Err(io::Error::other(
            "invalid native Internet database directory",
        ));
    }
    let limits = dns::Limits::default();
    let servers = dns::servers(limits)?;
    if servers.len() > limits.servers {
        return Err(io::Error::other("native DNS server bound was exceeded"));
    }
    let observed = dns::configuration(limits)?;
    if observed.servers?.len() > limits.servers {
        return Err(io::Error::other(
            "native DNS configuration exceeded server capacity",
        ));
    }
    if let Some(domain) = observed.domain?
        && (domain.name.is_empty() || domain.name.encode_utf16().count() >= limits.domain_units)
    {
        return Err(io::Error::other("invalid native DNS search domain"));
    }
    Ok(())
}
