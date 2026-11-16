//! Native DNS helper options, packet pumping and platform provisioning.
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};
#[cfg(target_os = "linux")]
mod linux;
mod pump;
#[cfg(target_os = "linux")]
pub use linux::run;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod pf;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub use bsd::run;
/// Fixed official six-argument helper configuration, validated before privilege IO.
pub struct Options {
    /// Requested exclusive native TUN name; macOS accepts utun or utunN.
    pub interface: String,
    /// Configured actual address.
    pub ipv6: Ipv6Addr,
    /// Actual native prefix.
    pub prefix: u8,
    /// Configured actual IPv4 address.
    pub ipv4: Ipv4Addr,
    /// Configured actual contiguous IPv4 mask.
    pub mask: Ipv4Addr,
    /// Official SKIP_ROUTING_SETUP, addresses/TUN still real.
    pub skip_routing: bool,
}
fn validate(options: &Options) -> io::Result<()> {
    let mask = u32::from(options.mask);
    let prefix = mask.leading_ones();
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if options.interface.is_empty()
        || options.interface.len() >= 16
        || !options
            .interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        || options.prefix > 128
        || mask != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DNS helper interface/address mask",
        ));
    }
    Ok(())
}
