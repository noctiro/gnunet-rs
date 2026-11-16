//! Reentrant native POSIX calendar conversion and byte formatting.
use super::super::{cstring, wide_micros};
use super::WallTime;
use std::{io, mem::MaybeUninit};
/// Native calendar fields and their microsecond display value.
pub(crate) struct Calendar {
    pub(crate) micros: i64,
    local: Option<libc::tm>,
}
pub(crate) fn wall_time() -> io::Result<WallTime> {
    let mut time = MaybeUninit::uninit();
    #[expect(
        unsafe_code,
        reason = "OS writes exactly one timeval to valid caller storage; timezone argument is unused"
    )]
    // SAFETY: output is aligned and writable; gettimeofday does not retain it.
    let status = unsafe { libc::gettimeofday(time.as_mut_ptr(), std::ptr::null_mut()) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    #[expect(
        unsafe_code,
        reason = "gettimeofday success initialized the exact timeval output"
    )]
    // SAFETY: the preceding successful call filled the output.
    let time = unsafe { time.assume_init() };
    Ok(WallTime {
        seconds: time.tv_sec,
        micros: wide_micros(time.tv_usec),
    })
}
impl Calendar {
    pub(crate) fn new(seconds: i64, micros: i64, utc: bool) -> io::Result<Self> {
        let value: libc::time_t = seconds;
        let mut out = MaybeUninit::uninit();
        #[expect(
            unsafe_code,
            reason = "Reentrant native calendar conversion with valid borrowed input and unique output"
        )]
        // SAFETY: pointers refer to valid time_t and writable tm; null means range failure.
        let result = unsafe {
            if utc {
                libc::gmtime_r(&value, out.as_mut_ptr())
            } else {
                libc::localtime_r(&value, out.as_mut_ptr())
            }
        };
        let local = if result.is_null() {
            None
        } else {
            #[expect(
                unsafe_code,
                reason = "Non-null reentrant calendar result initialized this output tm"
            )]
            // SAFETY: localtime_r/gmtime_r returned our initialized output pointer.
            Some(unsafe { out.assume_init() })
        };
        Ok(Self { micros, local })
    }
    pub(crate) fn format(&self, pattern: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
        let Some(local) = &self.local else {
            return Err(io::Error::other("localtime error"));
        };
        let pattern = cstring(pattern)?;
        let mut output = vec![0; capacity];
        #[expect(
            unsafe_code,
            reason = "Native strftime receives initialized tm and C format, bounded writable byte buffer"
        )]
        // SAFETY: output length is exactly the provided capacity and all inputs outlive the call.
        let count = unsafe {
            libc::strftime(
                output.as_mut_ptr().cast(),
                output.len(),
                pattern.as_ptr(),
                local,
            )
        };
        if count == 0 {
            return Err(io::Error::other("strftime returned zero"));
        }
        output.truncate(count);
        Ok(output)
    }
}
