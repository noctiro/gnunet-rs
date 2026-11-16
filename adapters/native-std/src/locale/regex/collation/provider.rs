//! Windows inbox ICU layouts and same-thread legacy COM reference ownership.
use crate::{com::Apartment, library::Library};
use std::{
    ffi::{CStr, c_void},
    io,
};
#[derive(Clone, Copy)]
pub(super) enum Part {
    Common,
    Collation,
}
pub(super) struct Provider {
    collation: Library,
    common: Option<Library>,
    _apartment: Option<Apartment>,
}
impl Provider {
    #[expect(
        unsafe_code,
        reason = "Only documented absolute Windows system-directory ICU providers and their stable C ABI are trusted; original references remain owned through every native object"
    )]
    pub fn load() -> io::Result<Self> {
        let directory = crate::paths::system_directory()?;
        let combined = directory.join("icu.dll");
        if crate::paths::exists(&combined)? {
            // SAFETY: selected Windows inbox combined ICU provider and dependencies.
            let collation = unsafe { Library::load(&combined) }?;
            return Ok(Self {
                collation,
                common: None,
                _apartment: None,
            });
        }
        // Windows 10 1703/1709/1803/1809 use the two documented providers and
        // require COM initialization; an existing combined provider's load or
        // export error never falls back to a different layout.
        let apartment = Apartment::acquire()?;
        // SAFETY: fixed absolute system provider, with a same-thread COM reference.
        let common = unsafe { Library::load(&directory.join("icuuc.dll")) }?;
        // SAFETY: same documented legacy layout; common remains loaded for dependencies.
        let collation = unsafe { Library::load(&directory.join("icuin.dll")) }?;
        Ok(Self {
            collation,
            common: Some(common),
            _apartment: Some(apartment),
        })
    }
    pub fn symbol(&self, name: &CStr, part: Part) -> io::Result<*mut c_void> {
        match part {
            Part::Collation => self.collation.symbol(name),
            Part::Common => self.common.as_ref().unwrap_or(&self.collation).symbol(name),
        }
    }
    pub fn pin(&self) -> io::Result<()> {
        self.collation.pin_for_process()?;
        if let Some(common) = &self.common {
            common.pin_for_process()?;
        }
        Ok(())
    }
}
