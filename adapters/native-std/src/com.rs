//! Same-thread COM initialization references and preserved HRESULT failures.
use std::{fmt, io, marker::PhantomData, rc::Rc};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize,
};

#[derive(Debug)]
pub(crate) struct Error {
    operation: &'static str,
    status: i32,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: HRESULT 0x{:08x}",
            self.operation, self.status as u32
        )
    }
}
impl std::error::Error for Error {}
pub(crate) fn result(operation: &'static str, status: i32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(Error { operation, status }))
    }
}

pub(crate) struct Apartment(PhantomData<Rc<()>>);
impl Apartment {
    #[expect(
        unsafe_code,
        reason = "COM initialization acquires exactly one calling-thread reference; a changed-mode failure acquires none before trying the existing STA model"
    )]
    pub(crate) fn acquire() -> io::Result<Self> {
        // SAFETY: null reserved pointer and documented calling-thread initialization.
        let mut status = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
        if status == 0x80010106u32 as i32 {
            // SAFETY: RPC_E_CHANGED_MODE left the existing apartment unchanged.
            status = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
        }
        match status {
            0 | 1 => Ok(Self(PhantomData)), // S_OK and S_FALSE both acquire a reference.
            status => Err(io::Error::other(Error {
                operation: "CoInitializeEx",
                status,
            })),
        }
    }
}
impl Drop for Apartment {
    #[expect(
        unsafe_code,
        reason = "The non-Send guard releases one successful initialization reference on its original thread"
    )]
    fn drop(&mut self) {
        // SAFETY: exactly one successful initialization, on this same thread.
        unsafe { CoUninitialize() };
    }
}
