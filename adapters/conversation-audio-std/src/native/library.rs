//! Original codec/device loader references, selected without a CWD search on Windows.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[link(name = "dl")]
unsafe extern "C" {}
#[cfg(unix)]
mod unix {
    use crate::Error;
    use gnunet_types::Error as Fault;
    use std::{
        ffi::{CStr, c_char, c_void},
        ptr::NonNull,
        rc::Rc,
    };

    pub(crate) struct Library {
        handle: NonNull<c_void>,
    }
    fn loader_diagnostic(operation: &'static str, raw: *const c_char) -> Error {
        // SAFETY: POSIX dlerror returns NULL or a valid NUL-terminated diagnostic
        // until the next loader call. It is copied immediately, before any such call.
        if raw.is_null() {
            return Error::Loader {
                operation,
                detail: "native loader returned a null symbol/handle without a diagnostic".into(),
                truncated: false,
            };
        }
        // SAFETY: The non-null pointer above is the current loader's valid string.
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes();
        let n = bytes.len().min(1024);
        let mut detail = String::new();
        if detail.try_reserve_exact(n * 4).is_err() {
            return Fault::Capacity.into();
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in &bytes[..n] {
            if b.is_ascii_graphic() || *b == b' ' {
                detail.push(char::from(*b));
            } else {
                detail.push('\\');
                detail.push('x');
                detail.push(char::from(HEX[usize::from(*b >> 4)]));
                detail.push(char::from(HEX[usize::from(*b & 15)]));
            }
        }
        Error::Loader {
            operation,
            detail,
            truncated: bytes.len() > n,
        }
    }
    impl Library {
        pub(crate) fn open(names: &[&CStr], operation: &'static str) -> Result<Rc<Self>, Error> {
            let mut failure = None;
            for name in names {
                // SAFETY: Each fixed library name is NUL-terminated. NOW/LOCAL are
                // standard loader flags; no symbol is called until its ABI is bound.
                let raw = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
                if let Some(handle) = NonNull::new(raw) {
                    return Ok(Rc::new(Self { handle }));
                }
                // SAFETY: Fetch the actual current failed dlopen diagnostic immediately.
                let error = unsafe { libc::dlerror() };
                failure = Some(loader_diagnostic(operation, error));
            }
            Err(failure.unwrap_or_else(|| Fault::Unavailable.into()))
        }
        pub(crate) fn symbol(
            &self,
            name: &CStr,
            operation: &'static str,
        ) -> Result<*mut c_void, Error> {
            // SAFETY: The original owned handle is live, and name is NUL-terminated.
            // Clearing/checking dlerror distinguishes lookup failure from null data.
            let (symbol, error) = unsafe {
                let _old = libc::dlerror();
                let p = libc::dlsym(self.handle.as_ptr(), name.as_ptr());
                (p, libc::dlerror())
            };
            if !error.is_null() || symbol.is_null() {
                return Err(loader_diagnostic(operation, error));
            }
            Ok(symbol)
        }
    }
    impl Drop for Library {
        fn drop(&mut self) {
            // SAFETY: This is the final Rc owner after all codec/device handles using
            // these symbols were destroyed. No dangling function pointer is invoked.
            let _status = unsafe { libc::dlclose(self.handle.as_ptr()) };
        }
    }
}
#[cfg(unix)]
pub(crate) use unix::Library;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::Library;
