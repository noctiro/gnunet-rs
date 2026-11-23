//! Native Unix Internet protocol and service database queries.

use std::{ffi::CStr, io};
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
use std::{mem::MaybeUninit, ptr};

#[cfg(any(target_env = "musl", target_env = "ohos"))]
mod musl;

/// Synchronous access to the system protocol and service databases.
pub struct Database {
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
    scratch: Vec<MaybeUninit<usize>>,
}

impl Database {
    /// Create a database handle for native lookups.
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
            scratch: Vec::new(),
        })
    }

    /// Look up a protocol name or alias and return its host-order number.
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_env = "musl",
        target_env = "ohos"
    )))]
    #[expect(unsafe_code, reason = "libc fills a caller-owned protocol record")]
    pub fn protocol(&mut self, name: &CStr) -> io::Result<Option<u16>> {
        // SAFETY: libc borrows the live NUL-terminated name and initializes
        // the supplied protocol record when it returns a match.
        let entry = unsafe {
            self.lookup(|entry, buffer, len, matched| {
                getprotobyname_r(name.as_ptr(), entry, buffer, len, matched)
            })
        }?;
        entry.map(|entry| number(entry.p_proto)).transpose()
    }

    /// Look up a protocol name or alias and return its host-order number.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[expect(unsafe_code, reason = "Libinfo protocol records are thread-local")]
    pub fn protocol(&mut self, name: &CStr) -> io::Result<Option<u16>> {
        let value = with_errno(|| {
            // SAFETY: the name is a live C string. On success Libinfo gives
            // this thread a readable record. Copy its scalar immediately.
            unsafe { libc::getprotobyname(name.as_ptr()).as_ref() }.map(|entry| entry.p_proto)
        })?;
        value.map(number).transpose()
    }

    /// Bionic documents all protocol name lookups as absent.
    #[cfg(target_os = "android")]
    pub fn protocol(&mut self, _name: &CStr) -> io::Result<Option<u16>> {
        Ok(None)
    }

    /// Look up a protocol name in musl's fixed table and return its host-order number.
    #[cfg(any(target_env = "musl", target_env = "ohos"))]
    pub fn protocol(&mut self, name: &CStr) -> io::Result<Option<u16>> {
        Ok(musl::protocol(name))
    }

    /// Look up a service for the exact protocol name and return its host-order port.
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
    #[expect(unsafe_code, reason = "libc fills a caller-owned service record")]
    pub fn service(&mut self, service: &CStr, protocol: &CStr) -> io::Result<Option<u16>> {
        let musl_semantics = cfg!(any(target_env = "musl", target_env = "ohos"));
        if musl_semantics && !matches!(protocol.to_bytes(), b"tcp" | b"udp") {
            // musl returns EINVAL for these protocols before searching /etc/services.
            // https://git.musl-libc.org/cgit/musl/tree/src/network/getservbyname_r.c
            return Ok(None);
        }
        // SAFETY: libc borrows the live C strings and initializes the
        // supplied service record when it returns a match.
        let entry = unsafe {
            self.lookup(|entry, buffer, len, matched| {
                let status = getservbyname_r(
                    service.as_ptr(),
                    protocol.as_ptr(),
                    entry,
                    buffer,
                    len,
                    matched,
                );
                if musl_semantics && status == libc::ENOENT {
                    // musl reports an absent service with ENOENT.
                    0
                } else {
                    status
                }
            })
        }?;
        entry
            .map(|entry| number(entry.s_port).map(u16::from_be))
            .transpose()
    }

    /// Look up a service for the exact protocol name and return its host-order port.
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "android"))]
    #[expect(
        unsafe_code,
        reason = "Darwin Libinfo and Android Bionic return thread-local service records"
    )]
    pub fn service(&mut self, service: &CStr, protocol: &CStr) -> io::Result<Option<u16>> {
        let value = with_errno(|| {
            // SAFETY: both names are live C strings. On success the native
            // result belongs to this thread. Copy its scalar immediately.
            unsafe { libc::getservbyname(service.as_ptr(), protocol.as_ptr()).as_ref() }
                .map(|entry| entry.s_port)
        })?;
        value.map(|port| number(port).map(u16::from_be)).transpose()
    }

    /// The callback must initialize the supplied record if it returns success
    /// with a nonnull match pointer.
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
    #[expect(
        unsafe_code,
        reason = "the caller supplies the native initialization contract"
    )]
    unsafe fn lookup<T>(
        &mut self,
        mut lookup: impl FnMut(*mut T, *mut libc::c_char, usize, *mut *mut T) -> libc::c_int,
    ) -> io::Result<Option<T>> {
        const INITIAL_WORDS: usize = 1024 / size_of::<usize>();
        const MAX_WORDS: usize = 64 * 1024 / size_of::<usize>();

        if self.scratch.is_empty() {
            self.resize_scratch(INITIAL_WORDS)?;
        }
        loop {
            let mut entry = MaybeUninit::<T>::uninit();
            let mut matched = ptr::null_mut();
            let status = lookup(
                entry.as_mut_ptr(),
                self.scratch.as_mut_ptr().cast(),
                size_of_val(self.scratch.as_slice()),
                &mut matched,
            );
            match status {
                0 if matched.is_null() => return Ok(None),
                0 if matched == entry.as_mut_ptr() => {
                    // SAFETY: a successful matching callback initialized entry.
                    return Ok(Some(unsafe { entry.assume_init() }));
                }
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "native registry returned an unexpected record address",
                    ));
                }
                libc::ERANGE if self.scratch.len() < MAX_WORDS => {
                    self.resize_scratch(self.scratch.len() * 2)?;
                }
                code => return Err(io::Error::from_raw_os_error(code)),
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
    fn resize_scratch(&mut self, words: usize) -> io::Result<()> {
        // The scratch stores native alias pointers as well as string bytes.
        self.scratch
            .try_reserve_exact(words - self.scratch.len())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        self.scratch.resize_with(words, MaybeUninit::uninit);
        Ok(())
    }
}

fn number(value: libc::c_int) -> io::Result<u16> {
    u16::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native registry number exceeds u16",
        )
    })
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "android"))]
#[expect(
    unsafe_code,
    reason = "Darwin and Bionic errno are read and restored on the calling thread"
)]
fn with_errno<T>(lookup: impl FnOnce() -> Option<T>) -> io::Result<Option<T>> {
    // SAFETY: libc supplies a writable errno slot for this thread. We only
    // use the pointer on this thread and retain no reference across the call.
    let (matched, code) = unsafe {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let errno = libc::__error();
        #[cfg(target_os = "android")]
        let errno = libc::__errno();
        let saved = errno.read();
        errno.write(0);
        let matched = lookup();
        let code = errno.read();
        errno.write(saved);
        (matched, code)
    };
    if matched.is_none() && code != 0 {
        return Err(io::Error::from_raw_os_error(code));
    }
    Ok(matched)
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
#[expect(
    unsafe_code,
    reason = "native libc reentrant lookup symbols from netdb.h"
)]
unsafe extern "C" {
    #[cfg(not(any(target_env = "musl", target_env = "ohos")))]
    fn getprotobyname_r(
        name: *const libc::c_char,
        entry: *mut libc::protoent,
        buffer: *mut libc::c_char,
        len: usize,
        matched: *mut *mut libc::protoent,
    ) -> libc::c_int;

    fn getservbyname_r(
        name: *const libc::c_char,
        protocol: *const libc::c_char,
        entry: *mut libc::servent,
        buffer: *mut libc::c_char,
        len: usize,
        matched: *mut *mut libc::servent,
    ) -> libc::c_int;
}
