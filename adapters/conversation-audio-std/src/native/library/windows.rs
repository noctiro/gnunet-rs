//! Side-by-side installed Opus DLLs; no process working-directory lookup.
use crate::Error;
use std::{
    ffi::{CStr, c_void},
    io,
    rc::Rc,
};
pub(crate) struct Library(gnunet_native::library::Library);
impl Library {
    pub(crate) fn open(names: &[&CStr], operation: &'static str) -> Result<Rc<Self>, Error> {
        let executable = std::env::current_exe().map_err(|source| Error::Io {
            operation,
            completed: 0,
            source,
        })?;
        let directory = executable
            .parent()
            .ok_or(gnunet_types::Error::InvalidInput)?;
        for name in names {
            let name = name
                .to_str()
                .map_err(|_| gnunet_types::Error::InvalidInput)?;
            let path = directory.join(name);
            match std::fs::metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(Error::Io {
                        operation,
                        completed: 0,
                        source,
                    });
                }
                Ok(metadata) if !metadata.is_file() => {
                    return Err(gnunet_types::Error::InvalidInput.into());
                }
                Ok(_) => {}
            }
            // SAFETY: fixed installed libopus candidates have the bound standard
            // C ABI. The shared loader restricts dependency lookup to the
            // installation directory and trusted system providers.
            let library =
                unsafe { gnunet_native::library::Library::load(&path) }.map_err(|source| {
                    Error::Io {
                        operation,
                        completed: 0,
                        source,
                    }
                })?;
            return Ok(Rc::new(Self(library)));
        }
        Err(Error::Io {
            operation,
            completed: 0,
            source: io::Error::new(
                io::ErrorKind::NotFound,
                "install libopus-0.dll or opus.dll beside the audio helper",
            ),
        })
    }
    pub(crate) fn symbol(
        &self,
        name: &CStr,
        operation: &'static str,
    ) -> Result<*mut c_void, Error> {
        self.0.symbol(name).map_err(|source| Error::Io {
            operation,
            completed: 0,
            source,
        })
    }
}
