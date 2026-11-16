//! Original-process resource observations with independent native failures.
use super::Process;
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle},
};
use windows_sys::Win32::{
    Foundation::FILETIME,
    System::{
        ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::{GetProcessIoCounters, GetProcessTimes, IO_COUNTERS},
    },
};

/// Actual CPU counters, converted from native 100-nanosecond units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuUsage {
    /// Sum of original process thread user CPU time, in microseconds.
    pub user_micros: u64,
    /// Sum of original process thread kernel CPU time, in microseconds.
    pub system_micros: u64,
}
/// Native memory high-water counters in bytes, without Unix unit assumptions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryUsage {
    /// Peak physical working set reported by the kernel.
    pub peak_working_set_bytes: u64,
    /// Peak process commit charge reported by the kernel.
    pub peak_commit_bytes: u64,
}
/// Original-process I/O operation and transfer counters, not Unix block counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoUsage {
    /// Actual read operations.
    pub read_operations: u64,
    /// Actual write operations.
    pub write_operations: u64,
    /// Actual operations other than reads/writes.
    pub other_operations: u64,
    /// Actual bytes transferred by reads.
    pub read_bytes: u64,
    /// Actual bytes transferred by writes.
    pub write_bytes: u64,
    /// Actual bytes transferred by other operations.
    pub other_bytes: u64,
}
/// Independent native queries from one pinned process object. A failed query
/// retains its original error; another successful query never supplies zeros for
/// it. Only an independently observed process exit makes these final counters.
#[derive(Debug)]
pub struct ResourceUsage {
    /// GetProcessTimes observation or original native error.
    pub cpu: io::Result<CpuUsage>,
    /// K32GetProcessMemoryInfo observation or original native error.
    pub memory: io::Result<MemoryUsage>,
    /// GetProcessIoCounters observation or original native error.
    pub io: io::Result<IoUsage>,
}
impl Process {
    /// Query this original process before releasing its handle. This neither
    /// waits nor consumes an exit receipt, and never opens a process by PID.
    pub fn resource_usage(&self) -> ResourceUsage {
        let handle = self.as_handle();
        ResourceUsage {
            cpu: cpu(handle),
            memory: memory(handle),
            io: io_counters(handle),
        }
    }
}
fn micros(value: FILETIME) -> u64 {
    ((u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)) / 10
}
#[expect(
    unsafe_code,
    reason = "GetProcessTimes borrows an original process handle and initialized exact FILETIME outputs, retaining no pointers"
)]
fn cpu(process: BorrowedHandle<'_>) -> io::Result<CpuUsage> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: original live handle and four distinct complete writable outputs.
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(CpuUsage {
        user_micros: micros(user),
        system_micros: micros(kernel),
    })
}
#[expect(
    unsafe_code,
    reason = "K32GetProcessMemoryInfo borrows the original process and exact initialized SDK counter storage with a checked size"
)]
fn memory(process: BorrowedHandle<'_>) -> io::Result<MemoryUsage> {
    let bytes = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS>()).map_err(io::Error::other)?;
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: bytes,
        ..Default::default()
    };
    // SAFETY: exact SDK layout, writable extent and original borrowed handle.
    if unsafe { K32GetProcessMemoryInfo(process.as_raw_handle(), &mut counters, bytes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(MemoryUsage {
        peak_working_set_bytes: u64::try_from(counters.PeakWorkingSetSize)
            .map_err(io::Error::other)?,
        peak_commit_bytes: u64::try_from(counters.PeakPagefileUsage).map_err(io::Error::other)?,
    })
}
#[expect(
    unsafe_code,
    reason = "GetProcessIoCounters writes one exact initialized SDK structure for an original borrowed process handle"
)]
fn io_counters(process: BorrowedHandle<'_>) -> io::Result<IoUsage> {
    let mut counters = IO_COUNTERS::default();
    // SAFETY: complete writable output and a live original handle, no retention.
    if unsafe { GetProcessIoCounters(process.as_raw_handle(), &mut counters) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(IoUsage {
        read_operations: counters.ReadOperationCount,
        write_operations: counters.WriteOperationCount,
        other_operations: counters.OtherOperationCount,
        read_bytes: counters.ReadTransferCount,
        write_bytes: counters.WriteTransferCount,
        other_bytes: counters.OtherTransferCount,
    })
}
