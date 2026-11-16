//! Original complete IP Helper interface table allocation and bounded rows.
use std::{
    io,
    ptr::{self, NonNull},
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
};

pub(super) struct Interfaces {
    raw: NonNull<MIB_IF_TABLE2>,
    count: usize,
}
impl Interfaces {
    #[expect(
        unsafe_code,
        reason = "The SDK supplies one complete initialized table allocation; its declared row extent is bounded before any slice is formed"
    )]
    pub fn capture(bound: usize) -> io::Result<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: the exact writable SDK output receives one original allocation.
        let status = unsafe { GetIfTable2(&mut raw) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut table = Self {
            raw: NonNull::new(raw)
                .ok_or_else(|| io::Error::other("null native interface table"))?,
            count: 0,
        };
        // SAFETY: the successful getter initialized the complete table header.
        let count = unsafe { table.raw.as_ref().NumEntries } as usize;
        if bound == 0
            || count > bound
            || count
                .checked_mul(size_of::<MIB_IF_ROW2>())
                .is_none_or(|bytes| bytes > isize::MAX as usize)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "native interface table exceeds its complete-snapshot bound",
            ));
        }
        table.count = count;
        Ok(table)
    }
    #[expect(
        unsafe_code,
        reason = "The original SDK allocation retains all initialized rows at their documented aligned trailing-array offset"
    )]
    pub fn rows(&self) -> &[MIB_IF_ROW2] {
        // SAFETY: capture bounded the full native extent; this borrow cannot
        // outlive the allocation or expose an incomplete prefix as a table.
        unsafe {
            std::slice::from_raw_parts(
                ptr::addr_of!((*self.raw.as_ptr()).Table).cast::<MIB_IF_ROW2>(),
                self.count,
            )
        }
    }
}
impl Drop for Interfaces {
    #[expect(
        unsafe_code,
        reason = "This is the single original allocation returned by the matching IP Helper getter"
    )]
    fn drop(&mut self) {
        // SAFETY: the original allocation is uniquely owned and freed once.
        unsafe { FreeMibTable(self.raw.as_ptr().cast()) };
    }
}
