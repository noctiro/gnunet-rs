//! Bounded primary and adapter DNS suffix observations; no resolver policy API.
use super::{IfOperStatusUp, Snapshot, invalid};
use std::{
    io,
    mem::{offset_of, size_of},
};
use windows_sys::Win32::{
    Foundation::ERROR_MORE_DATA,
    NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH,
    System::SystemInformation::{ComputerNameDnsDomain, GetComputerNameExW},
};

/// Native origin of the selected single search domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// Primary DNS domain returned by GetComputerNameExW.
    Primary,
    /// Connection-specific suffix of one operational adapter. A zero index
    /// means that native address-family index is unavailable, without mapping
    /// the other family's index into it.
    Interface {
        /// Actual IPv4 interface index from the native adapter header.
        ipv4_index: u32,
        /// Actual IPv6 interface index from the same native adapter record.
        ipv6_index: u32,
    },
}
/// An owned Unicode domain observation, without any peer authentication claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchDomain {
    /// Native UTF-16 decoded to valid UTF-8, without trimming or case folding.
    pub name: String,
    /// Exact source used to select this suffix.
    pub source: Source,
}
fn decode(units: &[u16]) -> io::Result<String> {
    let mut value = String::new();
    value
        .try_reserve_exact(
            units
                .len()
                .checked_mul(3)
                .ok_or(io::ErrorKind::OutOfMemory)?,
        )
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for unit in char::decode_utf16(units.iter().copied()) {
        value.push(unit.map_err(|_| invalid("DNS suffix contains invalid UTF-16"))?);
    }
    Ok(value)
}
// A success length excludes the NUL; MORE_DATA includes it. Only success data
// is interpreted, and every retry owns initialized storage with its exact bound.
fn primary_query(
    maximum: usize,
    mut query: impl FnMut(&mut [u16], &mut u32) -> io::Result<()>,
) -> io::Result<Option<String>> {
    if !(1..=32768).contains(&maximum) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut buffer = Vec::new();
    let mut capacity = maximum.min(64);
    let mut last_growth = None;
    for _ in 0..3 {
        buffer
            .try_reserve_exact(capacity - buffer.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        buffer.resize(capacity, 0);
        let mut units = buffer.len() as u32;
        match query(&mut buffer, &mut units) {
            Ok(()) => {
                let length = units as usize;
                if length >= buffer.len() || buffer[length] != 0 || buffer[..length].contains(&0) {
                    return Err(invalid("invalid native primary DNS domain extent"));
                }
                return if length == 0 {
                    Ok(None)
                } else {
                    decode(&buffer[..length]).map(Some)
                };
            }
            Err(error) if error.raw_os_error() == Some(ERROR_MORE_DATA as i32) => {
                let required = units as usize;
                if required <= capacity || required > maximum {
                    return Err(io::Error::new(io::ErrorKind::OutOfMemory, error));
                }
                capacity = required;
                last_growth = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(match last_growth {
        Some(error) => io::Error::new(io::ErrorKind::Interrupted, error),
        None => io::Error::new(
            io::ErrorKind::Interrupted,
            "primary DNS query did not complete",
        ),
    })
}
#[expect(
    unsafe_code,
    reason = "GetComputerNameExW borrows initialized bounded UTF-16 output and one scalar count; no pointer or ownership escapes"
)]
pub(super) fn primary(maximum: usize) -> io::Result<Option<SearchDomain>> {
    primary_query(maximum, |buffer, units| {
        // SAFETY: output and count are initialized exclusive borrows, with the
        // exact WCHAR capacity supplied for this synchronous native query.
        if unsafe { GetComputerNameExW(ComputerNameDnsDomain, buffer.as_mut_ptr(), units) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
    .map(|value| {
        value.map(|name| SearchDomain {
            name,
            source: Source::Primary,
        })
    })
}
impl Snapshot {
    #[expect(
        unsafe_code,
        reason = "Only checked plain SDK records and u16 units inside the original initialized adapter allocation are read"
    )]
    pub(super) fn domain(&self, maximum: usize) -> io::Result<Option<SearchDomain>> {
        let mut adapter = self.base().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut remaining = 8192usize;
        while !adapter.is_null() {
            remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| invalid("native DNS adapter traversal bound"))?;
            let length = self.record_length(
                adapter.cast(),
                offset_of!(IP_ADAPTER_ADDRESSES_LH, Ipv6IfIndex) + size_of::<u32>(),
            )?;
            // SAFETY: the checked plain SDK prefix contains all accessed fields.
            let info = unsafe { self.read(adapter, length)? };
            adapter = info.Next;
            if info.OperStatus != IfOperStatusUp || info.DnsSuffix.is_null() {
                continue;
            }
            let mut units = Vec::new();
            units
                .try_reserve_exact(maximum)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            let mut terminated = false;
            for at in 0..maximum {
                // SAFETY: read checks this complete u16 against the initialized
                // original snapshot before copying, including unaligned input.
                let unit =
                    unsafe { self.read::<u16>(info.DnsSuffix.wrapping_add(at), size_of::<u16>())? };
                if unit == 0 {
                    terminated = true;
                    break;
                }
                units.push(unit);
            }
            if !terminated {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "adapter DNS suffix exceeds explicit capacity",
                ));
            }
            if units.is_empty() {
                continue;
            }
            // SAFETY: the checked adapter prefix includes its plain ULONG index.
            let index = unsafe { info.Anonymous1.Anonymous.IfIndex };
            if index == 0 && info.Ipv6IfIndex == 0 {
                return Err(invalid("DNS suffix adapter has no native index"));
            }
            return Ok(Some(SearchDomain {
                name: decode(&units)?,
                source: Source::Interface {
                    ipv4_index: index,
                    ipv6_index: info.Ipv6IfIndex,
                },
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assertions qualify native length conventions, growth and genuine empty domains"
    )]
    fn primary_growth_empty_and_invalid_native_text_stay_distinct() -> io::Result<()> {
        let mut calls = 0;
        let name = primary_query(256, |buffer, units| {
            calls += 1;
            if calls == 1 {
                *units = 128;
                return Err(io::Error::from_raw_os_error(ERROR_MORE_DATA as i32));
            }
            buffer[..4].copy_from_slice(&[0x4f8b, 46, 120, 0]);
            *units = 3;
            Ok(())
        })?;
        assert_eq!(name.as_deref(), Some("例.x"));
        assert_eq!(calls, 2);
        assert_eq!(
            primary_query(256, |_, units| {
                *units = 0;
                Ok(())
            })?,
            None
        );
        assert!(
            primary_query(256, |buffer, units| {
                buffer[0] = 0xd800;
                *units = 1;
                Ok(())
            })
            .is_err()
        );
        assert!(
            primary_query(256, |_, units| {
                *units = 256;
                Ok(())
            })
            .is_err()
        );
        Ok(())
    }
}
