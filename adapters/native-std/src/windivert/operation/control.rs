//! Original-handle native queries and the two admitted kernel loans.
use super::{Loan, admission::Admission};
use crate::windivert::abi::Api;
use std::{io, sync::Arc};
use windows_sys::Win32::{
    Foundation::{ERROR_IO_INCOMPLETE, GetLastError, HANDLE},
    System::IO::GetOverlappedResult,
};

pub(in crate::windivert) struct Control(Admission<Loan>);
impl Control {
    pub fn new(original: usize) -> Self {
        Self(Admission::new(original))
    }

    pub fn original(&self) -> io::Result<usize> {
        self.0.original()
    }

    pub(super) fn submit(
        &mut self,
        owner: &Arc<Loan>,
        submit: impl FnOnce(HANDLE) -> io::Result<()>,
    ) -> io::Result<()> {
        self.0
            .submit(owner.kind, owner, |handle| submit(handle as HANDLE))
    }

    /// Called only by the original event callback, before it publishes memory
    /// retirement or releases directional credit. The slot is removed first.
    pub(super) fn complete(&mut self, owner: &Arc<Loan>) -> io::Result<io::Result<u32>> {
        self.0.complete(owner.kind, owner, Self::query)
    }

    #[expect(
        unsafe_code,
        reason = "The admission owner samples only its still-registered original loans under the original handle mutex, then invokes the one native close without waiting or duplicating the filter"
    )]
    pub fn close(&mut self, api: &Api) -> io::Result<()> {
        self.0.close(
            |handle, original| {
                let observation = Self::query(handle, original);
                if observation
                    .as_ref()
                    .is_err_and(|error| error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32))
                {
                    None
                } else {
                    Some(observation)
                }
            },
            |handle| {
                // SAFETY: admission was already removed under the one original
                // mutex; no query, cancellation or submission can use it again.
                if unsafe { (api.close)(handle as HANDLE) } == 0 {
                    // SAFETY: capture this close call's original thread error
                    // before another native call can replace it.
                    return Err(unsafe { GetLastError() } as i32);
                }
                Ok(())
            },
        )
    }

    #[expect(
        unsafe_code,
        reason = "Only the original admission owner queries this exact still-registered stable OVERLAPPED under the handle mutex, before callback publication can return its memory to Rust"
    )]
    fn query(handle: usize, original: &Loan) -> io::Result<u32> {
        let mut bytes = 0;
        // SAFETY: the live callback Arc pins this original allocation, and the
        // admission slot prevents publication until this query has returned.
        let overlapped = unsafe { std::ptr::addr_of_mut!((*original.memory.get()).overlapped) };
        // SAFETY: same original handle/OVERLAPPED, initialized output, no wait.
        if unsafe { GetOverlappedResult(handle as HANDLE, overlapped, &mut bytes, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(bytes)
    }
}
