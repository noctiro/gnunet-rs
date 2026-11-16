//! Original POSIX strptime/mktime policy, including partial-field normalization.
use crate::native::cstring;
#[cfg(not(target_os = "freebsd"))]
use libc::strptime;
use std::io;
#[cfg(target_os = "freebsd")]
#[expect(
    unsafe_code,
    reason = "FreeBSD time.h declares strptime with this ABI; pinned libc omits its Rust declaration"
)]
unsafe extern "C" {
    fn strptime(
        input: *const libc::c_char,
        format: *const libc::c_char,
        time: *mut libc::tm,
    ) -> *mut libc::c_char;
}

pub(crate) fn absolute_calendar(input: &[u8]) -> io::Result<u64> {
    let input = cstring(input)?;
    #[expect(
        unsafe_code,
        reason = "All integer and raw-pointer fields of native tm admit zero, matching source memset"
    )]
    // SAFETY: libc tm contains only C integers and nullable raw pointers.
    let mut calendar: libc::tm = unsafe { std::mem::zeroed() };
    let end = input.as_bytes().len();
    let mut complete = false;
    for pattern in [
        c"%a %b %d %H:%M:%S %Y",
        c"%c",
        c"%Ec",
        c"%Y-%m-%d %H:%M:%S",
        c"%Y-%m-%d %H:%M",
        c"%x",
        c"%Ex",
        c"%Y-%m-%d",
        c"%Y-%m",
        c"%Y",
    ] {
        #[expect(
            unsafe_code,
            reason = "Valid C input/format and uniquely borrowed tm; partial fields intentionally survive failed formats as in source"
        )]
        // SAFETY: pointers remain live; strptime mutates only this initialized tm.
        let result = unsafe { strptime(input.as_ptr(), pattern.as_ptr(), &mut calendar) };
        if !result.is_null() && result.addr() == input.as_ptr().addr() + end {
            complete = true;
            break;
        }
    }
    if !complete {
        return Err(io::Error::other("invalid absolute time"));
    }
    #[expect(
        unsafe_code,
        reason = "Native mktime receives initialized caller-owned tm and normalizes it in place"
    )]
    // SAFETY: calendar is live, initialized and uniquely borrowed.
    let seconds = unsafe { libc::mktime(&mut calendar) };
    if seconds == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((seconds as u64).saturating_mul(1_000_000))
}
