//! One original native loader reference, retained by every API/object owner.
use crate::Error;
use gnunet_native::library::Library as Native;
use std::{
    ffi::{CStr, c_void},
    io,
    path::Path,
    rc::Rc,
};

pub(super) struct Library(Native);
impl Library {
    pub(super) unsafe fn open(
        path: Option<&Path>,
        names: &[&CStr],
        operation: &'static str,
        before_native: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<Rc<Self>, Error> {
        if let Some(path) = path {
            before_native()?;
            // SAFETY: caller certifies the explicit provider and native ABI.
            return unsafe { Native::load(path) }
                .map(|owner| Rc::new(Self(owner)))
                .map_err(|source| Error::Loader { operation, source });
        }
        #[cfg(unix)]
        {
            let mut failure = None;
            for name in names {
                before_native()?;
                // SAFETY: caller authorizes standard names and native search.
                match unsafe { Native::load_basename(name) } {
                    Ok(owner) => return Ok(Rc::new(Self(owner))),
                    Err(error) => failure = Some(error),
                }
            }
            Err(Error::Loader {
                operation,
                source: failure.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no QR provider names selected")
                }),
            })
        }
        #[cfg(windows)]
        {
            let _names = names;
            Err(Error::Loader {
                operation,
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Windows QR providers require explicit absolute DLL paths",
                ),
            })
        }
    }
    pub(super) fn symbol(
        &self,
        name: &CStr,
        before_native: &mut impl FnMut() -> Result<(), Error>,
    ) -> Result<*mut c_void, Error> {
        before_native()?;
        self.0.symbol(name).map_err(|source| Error::Loader {
            operation: "resolve QR provider export",
            source,
        })
    }
}
