//! The actual GNU libc NSS host-address ABI; caller storage owns every pointer.
use crate::{Completion, Error, Family, Limits, Outcome};
use libc::{c_char, c_int, c_void, hostent, size_t, socklen_t};
use std::{
    mem::{align_of, size_of},
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};
const TRYAGAIN: c_int = -2;
const UNAVAIL: c_int = -1;
const NOTFOUND: c_int = 0;
const SUCCESS: c_int = 1;
const TRY_AGAIN: c_int = 2;
const NO_RECOVERY: c_int = 3;
const NO_DATA: c_int = 4;
#[derive(Clone, Copy)]
enum Profile {
    Both,
    V4,
    V6,
}
fn family(profile: Profile, af: c_int) -> Option<Family> {
    let af = if af == libc::AF_UNSPEC {
        if matches!(profile, Profile::V6) {
            libc::AF_INET6
        } else {
            libc::AF_INET
        }
    } else {
        af
    };
    match af {
        libc::AF_INET if !matches!(profile, Profile::V6) => Some(Family::V4),
        libc::AF_INET6 if !matches!(profile, Profile::V4) => Some(Family::V6),
        _ => None,
    }
}
unsafe fn status(
    status: c_int,
    errno: c_int,
    herr: c_int,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    // SAFETY: exported ABI validates these writable, aligned scalar pointers.
    unsafe {
        ptr::write(errnop, errno);
        ptr::write(h_errnop, herr);
    }
    status
}
fn errno(completion: &Completion) -> c_int {
    match completion.report.error.as_ref() {
        Some(Error::Busy | Error::Reentered) => libc::EAGAIN,
        Some(
            Error::Deadline
            | Error::Lookup(
                gnunet_gns_host::tld::Cause::NativeDeadline
                | gnunet_gns_host::tld::Cause::LogicalDeadline,
            ),
        ) => libc::ETIMEDOUT,
        Some(Error::Privileged) => libc::ENOENT,
        Some(Error::Protocol(gnunet_types::Error::Capacity)) => libc::ENOMEM,
        Some(
            Error::Protocol(gnunet_types::Error::InvalidInput | gnunet_types::Error::Malformed)
            | Error::Idna(_),
        ) => libc::EINVAL,
        Some(Error::Io(e)) => e.raw_os_error().unwrap_or(libc::EIO),
        Some(error) => {
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
            while let Some(e) = source {
                if let Some(io) = e.downcast_ref::<std::io::Error>() {
                    return io.raw_os_error().unwrap_or(libc::EIO);
                }
                source = e.source();
            }
            libc::EIO
        }
        None => libc::EIO,
    }
}
#[derive(Clone, Copy)]
struct Layout {
    alias: usize,
    name: usize,
    addresses: usize,
    pointers: usize,
}
fn aligned(base: usize, offset: usize, alignment: usize) -> Option<usize> {
    let absolute = base.checked_add(offset)?;
    let padding = (alignment - absolute % alignment) % alignment;
    offset.checked_add(padding)
}
fn layout(
    base: usize,
    available: usize,
    name: usize,
    count: usize,
    width: usize,
) -> Option<Layout> {
    let alias = aligned(base, 0, align_of::<*mut c_char>())?;
    let name_at = alias.checked_add(size_of::<*mut c_char>())?;
    // libc consumers can dereference each address as its native address
    // structure, independently of the address-list pointer table alignment.
    let addresses = aligned(
        base,
        name_at.checked_add(name)?.checked_add(1)?,
        align_of::<libc::in_addr>().max(align_of::<libc::in6_addr>()),
    )?;
    let pointers = aligned(
        base,
        addresses.checked_add(count.checked_mul(width)?)?,
        align_of::<*mut c_char>(),
    )?;
    let end = pointers.checked_add(
        count
            .checked_add(1)?
            .checked_mul(size_of::<*mut c_char>())?,
    )?;
    if available > isize::MAX as usize || end > available || base.checked_add(end).is_none() {
        None
    } else {
        Some(Layout {
            alias,
            name: name_at,
            addresses,
            pointers,
        })
    }
}
unsafe fn pack(
    result: *mut hostent,
    buffer: *mut c_char,
    name: &[u8],
    addresses: &[IpAddr],
    family: Family,
    positions: Layout,
) {
    let width = match family {
        Family::V4 => 4,
        Family::V6 => 16,
    };
    // SAFETY: layout preflight proves each offset/size fits the caller's
    // disjoint writable buffer; absolute-address alignment covers pointer slots.
    unsafe {
        let aliases = buffer.add(positions.alias).cast::<*mut c_char>();
        ptr::write(aliases, ptr::null_mut());
        let original_name = buffer.add(positions.name);
        ptr::copy_nonoverlapping(name.as_ptr(), original_name.cast::<u8>(), name.len());
        ptr::write(original_name.add(name.len()), 0);
        let pointers = buffer.add(positions.pointers).cast::<*mut c_char>();
        for (index, address) in addresses.iter().enumerate() {
            let address_at = buffer.add(positions.addresses + index * width);
            match address {
                IpAddr::V4(v) => {
                    ptr::copy_nonoverlapping(v.octets().as_ptr(), address_at.cast::<u8>(), 4)
                }
                IpAddr::V6(v) => {
                    ptr::copy_nonoverlapping(v.octets().as_ptr(), address_at.cast::<u8>(), 16)
                }
            }
            ptr::write(pointers.add(index), address_at);
        }
        ptr::write(pointers.add(addresses.len()), ptr::null_mut());
        ptr::write(
            result,
            hostent {
                h_name: original_name,
                h_aliases: aliases,
                h_addrtype: match family {
                    Family::V4 => libc::AF_INET,
                    Family::V6 => libc::AF_INET6,
                },
                h_length: width as c_int,
                h_addr_list: pointers,
            },
        );
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "Keep the caller's GNU NSS name2 ABI pointers and lengths explicit alongside the selected module profile"
)]
unsafe fn forward(
    profile: Profile,
    name: *const c_char,
    af: c_int,
    result: *mut hostent,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    if errnop.is_null() || h_errnop.is_null() {
        return UNAVAIL;
    }
    // SAFETY: all remaining scalar writes use caller-supplied writable pointers.
    unsafe {
        if name.is_null() || result.is_null() {
            return status(UNAVAIL, libc::EINVAL, NO_RECOVERY, errnop, h_errnop);
        }
        let Some(family) = family(profile, af) else {
            return status(UNAVAIL, libc::EINVAL, NO_RECOVERY, errnop, h_errnop);
        };
        let mut length = 0;
        while length <= 1024 {
            // The C ABI requires an actual NUL-terminated name allocation.
            if ptr::read(name.add(length)) == 0 {
                break;
            }
            length += 1;
        }
        if length == 0 || length > 1024 {
            return status(UNAVAIL, libc::EINVAL, NO_RECOVERY, errnop, h_errnop);
        }
        let name = std::slice::from_raw_parts(name.cast::<u8>(), length);
        if buffer.is_null() || layout(buffer as usize, buflen, length, 0, 0).is_none() {
            return status(TRYAGAIN, libc::ERANGE, NO_RECOVERY, errnop, h_errnop);
        }
        let completion = crate::lookup(name, family, Limits::default());
        if completion.report.failed() {
            let e = errno(&completion);
            return status(
                if matches!(completion.report.error, Some(Error::Busy)) {
                    TRYAGAIN
                } else {
                    UNAVAIL
                },
                e,
                if e == libc::EAGAIN {
                    TRY_AGAIN
                } else {
                    NO_RECOVERY
                },
                errnop,
                h_errnop,
            );
        }
        match &completion.outcome {
            Outcome::Addresses(addresses) => {
                if addresses.is_empty()
                    || addresses.iter().any(|address| {
                        !matches!(
                            (family, address),
                            (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_))
                        )
                    })
                {
                    return status(UNAVAIL, libc::EPROTO, NO_RECOVERY, errnop, h_errnop);
                }
                let width = match family {
                    Family::V4 => 4,
                    Family::V6 => 16,
                };
                let Some(positions) =
                    layout(buffer as usize, buflen, length, addresses.len(), width)
                else {
                    return status(TRYAGAIN, libc::ERANGE, NO_RECOVERY, errnop, h_errnop);
                };
                pack(result, buffer, name, addresses, family, positions);
                status(SUCCESS, 0, 0, errnop, h_errnop)
            }
            Outcome::NoData => status(NOTFOUND, 0, NO_DATA, errnop, h_errnop),
            Outcome::NotGns => status(UNAVAIL, libc::ENOENT, NO_RECOVERY, errnop, h_errnop),
            Outcome::Unavailable => {
                status(UNAVAIL, errno(&completion), NO_RECOVERY, errnop, h_errnop)
            }
        }
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "The unwind boundary forwards the exact caller-owned GNU NSS arguments without rebuilding an output owner"
)]
unsafe fn boundary(
    profile: Profile,
    name: *const c_char,
    af: c_int,
    result: *mut hostent,
    buffer: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    // SAFETY: every exported hook has the same documented GNU NSS contract.
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        forward(profile, name, af, result, buffer, buflen, errnop, h_errnop)
    }));
    match result {
        Ok(v) => v,
        Err(_payload) => {
            if errnop.is_null() || h_errnop.is_null() {
                UNAVAIL
            } else {
                // SAFETY: nonnull original scalar output pointers satisfy ABI contract.
                unsafe { status(UNAVAIL, libc::EIO, NO_RECOVERY, errnop, h_errnop) }
            }
        }
    }
}
macro_rules! exports {
    ($name:ident, $name2:ident, $addr:ident, $profile:expr) => {
        /// GNU NSS forward host-address lookup with the profile's default family.
        ///
        /// # Safety
        /// The name is a valid NUL-terminated C string. Output pointers are
        /// aligned, writable and mutually disjoint. Buffer denotes buflen bytes
        /// disjoint from name/result/scalars. No pointer may be concurrently used.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            name: *const c_char,
            result: *mut hostent,
            buffer: *mut c_char,
            buflen: size_t,
            errnop: *mut c_int,
            h_errnop: *mut c_int,
        ) -> c_int {
            // SAFETY: this hook forwards its complete unchanged GNU ABI contract.
            unsafe {
                boundary(
                    $profile,
                    name,
                    libc::AF_UNSPEC,
                    result,
                    buffer,
                    buflen,
                    errnop,
                    h_errnop,
                )
            }
        }
        /// GNU NSS forward host-address lookup for an explicit native family.
        ///
        /// # Safety
        /// The name is a valid NUL-terminated C string. Output pointers are
        /// aligned, writable and mutually disjoint. Buffer denotes buflen bytes
        /// disjoint from name/result/scalars. No pointer may be concurrently used.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name2(
            name: *const c_char,
            af: c_int,
            result: *mut hostent,
            buffer: *mut c_char,
            buflen: size_t,
            errnop: *mut c_int,
            h_errnop: *mut c_int,
        ) -> c_int {
            // SAFETY: this hook forwards its complete unchanged GNU ABI contract.
            unsafe { boundary($profile, name, af, result, buffer, buflen, errnop, h_errnop) }
        }
        /// GNU NSS reverse lookup, explicitly unavailable like the official module.
        ///
        /// # Safety
        /// If nonnull, errnop and h_errnop must be aligned, writable, disjoint
        /// integer outputs. Other arguments are not dereferenced or retained.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $addr(
            _addr: *const c_void,
            _len: socklen_t,
            _af: c_int,
            _result: *mut hostent,
            _buffer: *mut c_char,
            _buflen: size_t,
            errnop: *mut c_int,
            h_errnop: *mut c_int,
        ) -> c_int {
            if errnop.is_null() || h_errnop.is_null() {
                return UNAVAIL;
            }
            // SAFETY: only the two actual scalar output pointers are written.
            unsafe { status(UNAVAIL, libc::EINVAL, NO_RECOVERY, errnop, h_errnop) }
        }
    };
}
exports!(
    _nss_gns_gethostbyname_r,
    _nss_gns_gethostbyname2_r,
    _nss_gns_gethostbyaddr_r,
    Profile::Both
);
exports!(
    _nss_gns4_gethostbyname_r,
    _nss_gns4_gethostbyname2_r,
    _nss_gns4_gethostbyaddr_r,
    Profile::V4
);
exports!(
    _nss_gns6_gethostbyname_r,
    _nss_gns6_gethostbyname2_r,
    _nss_gns6_gethostbyaddr_r,
    Profile::V6
);
