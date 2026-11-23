//! Configure IPv4 forwarding and source-network masquerade inside a private router.

mod wire;

use super::{Ipv4Prefix, PrivateNetworkNamespace};
use crate::linux_netlink::Socket;
use nix::sys::statfs::{PROC_SUPER_MAGIC, fstatfs};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    time::Instant,
};

/// Enable the TESTING router's IPv4 forwarding and source-network masquerade.
///
/// The kernel installs the table, postrouting hook and rule as one transaction.
/// Forwarding is enabled after the table is visible. The kernel operations run
/// on the private namespace's worker under the original setup deadline.
///
/// # Errors
/// Refuses an existing `nat` table and preserves namespace, kernel transport
/// and sysctl errors. Retire the router after a failure because the table may
/// already have been committed.
pub fn enable_ipv4_masquerade(
    namespace: &PrivateNetworkNamespace,
    network: Ipv4Addr,
    prefix: Ipv4Prefix,
    deadline: Instant,
) -> io::Result<()> {
    check_deadline(deadline)?;
    namespace.with_worker(|| {
        check_deadline(deadline)?;
        let mut forwarding = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open("/proc/sys/net/ipv4/ip_forward")?;
        if fstatfs(&forwarding)?.filesystem_type() != PROC_SUPER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPv4 forwarding requires procfs",
            ));
        }

        let control = Socket::open(libc::NETLINK_NETFILTER)?;
        let batch = wire::create_masquerade(control.port(), network, prefix)?;
        let mut acknowledgements = wire::BatchAck::new(control.port());
        let mut reply = [0; 4096];
        control.send(&batch, deadline)?;
        while !acknowledgements.is_complete() {
            let size = control.receive(&mut reply, deadline)?;
            acknowledgements.accept(&reply[..size])?;
        }

        // Older kernels have no separate batch-end ACK. A read of the exact
        // newly created table distinguishes commit from per-operation ACKs.
        control.send(&wire::get_table(control.port())?, deadline)?;
        let size = control.receive(&mut reply, deadline)?;
        wire::confirm_table(control.port(), &reply[..size])?;
        check_deadline(deadline)?;
        forwarding.write_all(b"1\n")
    })
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TESTING router setup deadline expired",
        ));
    }
    Ok(())
}
