//! Exact five official positional arguments, with one explicit Rust MTU extension.
use crate::{Profile, failure::Failure};
use std::{
    ffi::{OsStr, OsString},
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::ffi::OsStrExt,
};
pub(super) const MAX_PACKET: usize = u16::MAX as usize - 8;
pub(super) struct Options {
    pub name: Vec<u8>,
    pub egress: Option<Vec<u8>>,
    pub v6: Option<(Ipv6Addr, u8)>,
    pub v4: Option<(Ipv4Addr, Ipv4Addr)>,
    pub mtu: Option<u32>,
}
fn text(value: &OsStr, maximum: usize) -> Result<&str, Failure> {
    if value.as_bytes().len() > maximum {
        return Err(Failure::invalid("arguments", "numeric argument too long"));
    }
    value
        .to_str()
        .ok_or_else(|| Failure::invalid("arguments", "numeric IP arguments must be ASCII"))
}
fn next(args: &mut impl Iterator<Item = OsString>) -> Result<OsString, Failure> {
    args.next().ok_or_else(|| {
        Failure::invalid(
            "arguments",
            "must supply exactly the selected helper positional arguments",
        )
    })
}
impl Options {
    pub fn parse(profile: Profile) -> Result<Self, Failure> {
        let mut args = std::env::args_os();
        drop(args.next());
        let name = next(&mut args)?;
        let egress = if matches!(profile, Profile::Exit) {
            Some(next(&mut args)?)
        } else {
            None
        };
        let v6 = next(&mut args)?;
        let prefix = next(&mut args)?;
        let v4 = next(&mut args)?;
        let mask = next(&mut args)?;
        if args.next().is_some() {
            return Err(Failure::invalid(
                "arguments",
                "must supply exactly the selected helper positional arguments",
            ));
        }
        let name = name.as_bytes();
        if name.len() >= libc::IFNAMSIZ || name.contains(&0) {
            return Err(Failure::invalid(
                "arguments",
                "interface name exceeds IFNAMSIZ or contains NUL",
            ));
        }
        let v6 = if v6.as_bytes() == b"-" {
            None
        } else {
            let address = text(&v6, 45)?
                .parse::<Ipv6Addr>()
                .map_err(|_| Failure::invalid("arguments", "invalid numeric IPv6 address"))?;
            let raw = text(&prefix, 3)?;
            if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Failure::invalid("arguments", "invalid IPv6 prefix"));
            }
            let prefix = raw
                .parse::<u8>()
                .map_err(|_| Failure::invalid("arguments", "invalid IPv6 prefix"))?;
            if !(1..=127).contains(&prefix) {
                return Err(Failure::invalid("arguments", "IPv6 prefix must be 1..127"));
            }
            Some((address, prefix))
        };
        let v4 = if v4.as_bytes() == b"-" {
            None
        } else {
            let address = text(&v4, 15)?
                .parse::<Ipv4Addr>()
                .map_err(|_| Failure::invalid("arguments", "invalid numeric IPv4 address"))?;
            let mask = text(&mask, 15)?
                .parse::<Ipv4Addr>()
                .map_err(|_| Failure::invalid("arguments", "invalid numeric IPv4 mask"))?;
            Some((address, mask))
        };
        // Presence, not provenance, selects the explicit Rust-only extension.
        // The original C helper does not read this environment variable.
        let mtu = std::env::var_os("GNUNET_VPN_HELPER_MTU")
            .map(|value| {
                let value = text(&value, 5)?;
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Failure::invalid("MTU", "MTU must be decimal"));
                }
                let value = value
                    .parse::<u32>()
                    .map_err(|_| Failure::invalid("MTU", "invalid MTU"))?;
                let minimum = if v6.is_some() { 1280 } else { 68 };
                if value < minimum || value > MAX_PACKET as u32 {
                    return Err(Failure::invalid(
                        "MTU",
                        "MTU outside IP/helper-frame bounds",
                    ));
                }
                Ok(value)
            })
            .transpose()?;
        if matches!(profile, Profile::Exit) && v4.is_none() && v6.is_none() {
            return Err(Failure::invalid(
                "EXIT arguments",
                "both IP families disabled",
            ));
        }
        let egress = egress
            .map(|value| {
                let bytes = value.as_bytes();
                if bytes == b"-" {
                    return Ok(None);
                }
                // iptables treats '+' as an interface wildcard. This contract names
                // one actual egress interface, never a wildcard or shell expression.
                if bytes.is_empty()
                    || bytes.len() >= libc::IFNAMSIZ
                    || bytes.contains(&0)
                    || bytes.contains(&b'+')
                    || bytes.contains(&b'/')
                    || bytes.iter().any(u8::is_ascii_whitespace)
                {
                    return Err(Failure::invalid(
                        "EXIT egress",
                        "expected one literal interface name or '-'",
                    ));
                }
                let mut owned = Vec::new();
                owned.try_reserve_exact(bytes.len()).map_err(|_| {
                    Failure::invalid("EXIT egress", "bounded interface allocation failed")
                })?;
                owned.extend_from_slice(bytes);
                Ok(Some(owned))
            })
            .transpose()?
            .flatten();
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(name.len())
            .map_err(|_| Failure::invalid("arguments", "interface-name allocation failed"))?;
        owned.extend_from_slice(name);
        Ok(Self {
            name: owned,
            egress,
            v6,
            v4,
            mtu,
        })
    }
}
